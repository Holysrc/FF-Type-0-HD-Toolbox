#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"

#include <Shlwapi.h>

#include <string_view>
#include <sstream>
#include <regex>
#include <math.h>
#include <cstdio>
#include <cstdarg>
#include <stdexcept>
#include <thread>
#include <commctrl.h>
#include <tlhelp32.h>
#pragma comment(lib, "Comctl32.lib")
#include "Utils/Trampoline.h"
#include "include/keystone/keystone.h"

#pragma comment(lib, "Shlwapi.lib")

wchar_t wcModulePath[MAX_PATH];
static HMODULE hDLLModule;

/*Keystone Imports*/
typedef ks_err(__stdcall* ks_open_dll)(ks_arch arch, int mode, ks_engine** ks);
typedef int(__stdcall* ks_asm_dll)(ks_engine* ks, const char* string, uint64_t address, unsigned char** encoding, size_t* encoding_size, size_t* stat_count);
typedef void(__stdcall* ks_free_dll)(unsigned char* p);

using namespace Memory::VP;
using namespace hook;

// ---------------------------------------------------------------------------
// Diagnostics logging & safe pattern lookup (robustness additions)
//
// The shipped build defines NDEBUG, which turns assert() into a no-op. The
// upstream pattern matcher relies on assert() to guarantee a match exists;
// with asserts disabled, a missing pattern reads element [0] of an empty
// vector and the mod then writes a patch to a garbage address, crashing the
// game straight to the desktop with no message. This is the most likely cause
// of the "white screen then exit on startup" reports on unexpected game
// versions (GitHub issues #18, #9, #16, #10).
//
// FindOne()/FindAll() validate the match count first, log the exact failing
// signature to "<mod>.log", and throw instead of corrupting memory. The whole
// patch pass is wrapped in a try/catch so a single missing signature degrades
// gracefully (mod does nothing / partially applies) instead of taking the
// game down, and the log names the signature that needs updating.
// ---------------------------------------------------------------------------
static wchar_t wcLogPath[MAX_PATH];
static bool g_logEnabled = false;

static void LogInit()
{
	if (!g_logEnabled)
		return;
	FILE* f = nullptr;
	if (_wfopen_s(&f, wcLogPath, L"w") == 0 && f)
		fclose(f);
}

static void LogF(const char* fmt, ...)
{
	if (!g_logEnabled)
		return;
	FILE* f = nullptr;
	if (_wfopen_s(&f, wcLogPath, L"a") != 0 || !f)
		return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

// Returns the single match for sig; logs the signature and throws if the match
// count is zero (which would otherwise be an out-of-bounds read). Multiple
// matches only warn and use the first one — that is what the shipped builds
// effectively did (get_one()'s count assert is a no-op under NDEBUG), and at
// least one signature legitimately matches twice on the Steam build.
static pattern_match FindOne(const char* sig)
{
	pattern pat(sig);
	const size_t n = pat.size();
	if (n == 0)
	{
		LogF("  [MISS] get_one matches=0  sig: %s", sig);
		throw std::runtime_error(sig);
	}
	if (n > 1)
		LogF("  [WARN] get_one matches=%zu, using first  sig: %s", n, sig);
	return pat.get(0);
}

// Returns the pattern for iteration. Never throws (an empty result simply
// iterates nothing), but logs when the count is unexpected. expected == 0
// means "any count, but still warn on zero".
static pattern FindAll(const char* sig, size_t expected)
{
	pattern pat(sig);
	const size_t n = pat.size();
	if (n == 0)
		LogF("  [MISS] for_each matches=0 expected=%zu  sig: %s", expected, sig);
	else if (expected != 0 && n != expected)
		LogF("  [WARN] for_each matches=%zu expected=%zu, patching all  sig: %s", n, expected, sig);
	return pat;
}

// Diagnostics counters living in trampoline memory, incremented from the
// injected ASM of the dedup-list patches:
// [0..4] free-slot-loop overflow events (fire trigger / audio trigger /
//        gameplay counters #1 / #2 / cutscene timings)
// [5]    peak slot INDEX ever used in the damage_and_audio_triggers list
// [6]    peak slot INDEX ever used in the floatcountersptrs list
// [7]    free-slot-loop overflow events of the script layer-wait patch
// [8]    free-slot-loop overflow events of the demo-scene Wait/TargetEffect patches
// A detached watcher thread samples them and appends a line to the log
// whenever anything changed, so list pressure can be correlated with in-game
// events (issue #12 softlock / #20 crashes) without a debugger attached.
static uint32_t* g_stats = nullptr;

// Sound-trace mode ([Diagnostics] TraceSounds=1): a hook on the game's central
// "request sound by id" function writes every id into this ring buffer; a
// watcher thread drains it into the log and also logs an F9 keypress marker,
// so in-game events (e.g. the Kill Sight cue) can be correlated with sound ids.
static uint32_t* g_sndRing = nullptr;
static volatile uint32_t* g_sndHead = nullptr;

// File-open interception (IAT hook on kernel32 CreateFileW/A):
// - [Diagnostics] TraceFiles=1 logs every file the game opens during the first
//   60 seconds (to identify the boot splash screen assets).
// - [Intro] SkipIntroVideos=1 makes the two opening movies (ep0101_opa /
//   ep0102_opb) fail to open, which the game handles by skipping them.
//   The list can be extended with logo assets once identified.
static decltype(&CreateFileW) g_origCreateFileW = nullptr;
static decltype(&CreateFileA) g_origCreateFileA = nullptr;
static bool g_traceFiles = false;
static bool g_skipIntroVideos = false;
static ULONGLONG g_fileHookStart = 0;

static bool IsIntroVideoPathA(const char* p)
{
	char low[512];
	size_t i = 0;
	for (; p[i] && i < 511; i++)
		low[i] = (p[i] >= 'A' && p[i] <= 'Z') ? p[i] + 32 : p[i];
	low[i] = 0;
	return strstr(low, "ep0101_opa") || strstr(low, "ep0102_opb");
}

static bool IsIntroVideoPathW(const wchar_t* p)
{
	char narrow[512];
	size_t i = 0;
	for (; p[i] && i < 511; i++)
		narrow[i] = (p[i] < 128) ? static_cast<char>(p[i]) : '?';
	narrow[i] = 0;
	return IsIntroVideoPathA(narrow);
}

static HANDLE WINAPI HookedCreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl)
{
	if (name)
	{
		if (g_traceFiles && GetTickCount64() - g_fileHookStart < 60000)
			LogF("[File] %ls", name);
		if (g_skipIntroVideos && IsIntroVideoPathW(name))
		{
			LogF("[SkipIntro] blocked %ls", name);
			SetLastError(ERROR_FILE_NOT_FOUND);
			return INVALID_HANDLE_VALUE;
		}
	}
	return g_origCreateFileW(name, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI HookedCreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl)
{
	if (name)
	{
		if (g_traceFiles && GetTickCount64() - g_fileHookStart < 60000)
			LogF("[File] %hs", name);
		if (g_skipIntroVideos && IsIntroVideoPathA(name))
		{
			LogF("[SkipIntro] blocked %hs", name);
			SetLastError(ERROR_FILE_NOT_FOUND);
			return INVALID_HANDLE_VALUE;
		}
	}
	return g_origCreateFileA(name, access, share, sa, disp, flags, tmpl);
}

static void PatchIAT(const char* funcName, void* hook, void** orig)
{
	auto base = reinterpret_cast<uint8_t*>(GetModuleHandle(nullptr));
	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
	auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!dir.VirtualAddress)
		return;
	for (auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); desc->Name; desc++)
	{
		if (_stricmp(reinterpret_cast<char*>(base + desc->Name), "kernel32.dll") != 0)
			continue;
		auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
		auto othunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
		for (; othunk->u1.AddressOfData; thunk++, othunk++)
		{
			if (othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;
			auto imp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + othunk->u1.AddressOfData);
			if (strcmp(imp->Name, funcName) == 0)
			{
				DWORD old;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
				*orig = reinterpret_cast<void*>(thunk->u1.Function);
				thunk->u1.Function = reinterpret_cast<ULONG_PTR>(hook);
				VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
				return;
			}
		}
	}
}

// Intro-video auto-skip: game assets live inside pack archives, so blocking
// them at the file level does nothing (CreateFile only ever sees pack0.pac).
// Instead we use the movie player's own skip pathway: while a movie is playing
// (state byte base+0x655ECC == 3) the per-frame updater checks three flag
// bytes (base+0x655ECD/CE/CF: skip-allowed / menu-armed / skip-confirmed) and,
// when set, runs its native skip handler (stops playback, resets state, the
// game continues normally). A watcher thread arms those flags whenever the
// currently playing path (ptr at base+0x655EE0) is one of the opening movies.
static uintptr_t g_introBase = 0;

static uintptr_t g_gameBase = 0;
static float g_framerate = 30.0f; //effective framerate, for diagnostics that compare fps
static volatile uint8_t g_bootPhaseOver; // set once the first movie is reached (defined below)

// Boot-scan diagnostic ([Diagnostics] BootScan=1): during the first 30s the
// logo slide index must advance slowly somewhere in .data (0->1->2->3...).
// Snapshot the whole .data/.bss range every 250ms and report dwords that only
// ever increment by 1, change at most a few times, at least 1.5s apart, and
// stay small — that shortlist should contain the slide state variable.
static void StartBootScanWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const uint32_t start_rva = 0x60B000;
		const uint32_t n = 0x3E2890;
		auto lastv = static_cast<uint8_t*>(malloc(n));
		auto lastt = static_cast<uint32_t*>(calloc(n, 4));
		auto firstt = static_cast<uint32_t*>(calloc(n, 4));
		auto cnt = static_cast<uint8_t*>(calloc(n, 1));
		auto bad = static_cast<uint8_t*>(calloc(n, 1));
		if (!lastv || !lastt || !firstt || !cnt || !bad)
			return;
		auto mem = reinterpret_cast<const volatile uint8_t*>(g_gameBase + start_rva);
		for (uint32_t i = 0; i < n; i++)
			lastv[i] = mem[i];
		const ULONGLONG t0 = GetTickCount64();
		ULONGLONG overAt = 0;
		for (;;)
		{
			Sleep(250);
			const uint32_t now = static_cast<uint32_t>(GetTickCount64() - t0);
			if (now > 30000)
				break;
			// slides are over once the first movie starts; report shortly after
			if (!overAt && (g_bootPhaseOver || *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x655ECC) != 0))
				overAt = GetTickCount64();
			if (overAt && GetTickCount64() - overAt > 2000)
				break;
			for (uint32_t i = 0; i < n; i++)
			{
				const uint8_t v = mem[i];
				if (v == lastv[i])
					continue;
				if (v > 64)
					bad[i] = 1;
				else if (cnt[i] && now - lastt[i] < 1200)
					bad[i] = 1;
				if (!cnt[i])
					firstt[i] = now;
				if (cnt[i] < 250)
					cnt[i]++;
				lastt[i] = now;
				lastv[i] = v;
			}
		}
		// pass 1: mark hits, then report isolated ones (no other hit within
		// 64 bytes) individually — buffer-wide churn collapses into regions
		auto hit = bad; // reuse: 1 = qualifying candidate
		for (uint32_t i = 0; i < n; i++)
			hit[i] = (!bad[i] && cnt[i] >= 2 && cnt[i] <= 12) ? 1 : (bad[i] = 0);
		int singles = 0, regions = 0;
		for (uint32_t i = 0; i < n; i++)
		{
			if (!hit[i])
				continue;
			uint32_t j = i;
			while (j + 1 < n)
			{
				bool more = false;
				for (uint32_t k = j + 1; k < j + 65 && k < n; k++)
					if (hit[k]) { j = k; more = true; break; }
				if (!more) break;
			}
			if (j == i)
			{
				if (singles < 60)
					LogF("[BootScan] SINGLE rva=0x%X changes=%u final=%u t=%u..%ums", start_rva + i, cnt[i], lastv[i], firstt[i], lastt[i]);
				singles++;
			}
			else
			{
				if (regions < 40)
					LogF("[BootScan] region 0x%X..0x%X (%u bytes changed)", start_rva + i, start_rva + j, j - i + 1);
				regions++;
			}
			i = j;
		}
		LogF("[BootScan] done: %d singles, %d regions", singles, regions);
		free(lastv); free(lastt); free(firstt); free(cnt); free(bad);
	}).detach();
}

// Boot auto-confirm ([Intro] AutoSkipSplash=1): the boot flow shows an
// autosave notice (dismissed with Enter/A) and then logo slides (skippable
// with Start). Synthesize Enter presses while the game window is focused,
// until the first movie starts (whose skip is handled separately) or 40s pass.
static bool g_autoSkipSplash = false;

// Boot trace ([Diagnostics] BootTrace=1): samples the boot sequencer's state
// every 250ms for 30s — both tick counters, the pending-item deque pointers
// and the movie state — to understand how the logo slides are actually timed.
static void StartBootTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 30000)
		{
			Sleep(250);
			const uint32_t timerA = *reinterpret_cast<volatile uint32_t*>(g_gameBase + 0x6C4BCC);
			const uint32_t timerB = *reinterpret_cast<volatile uint32_t*>(g_gameBase + 0x63F178);
			const uint64_t qbegin = *reinterpret_cast<volatile uint64_t*>(g_gameBase + 0x63D1D8);
			const uint64_t qend = *reinterpret_cast<volatile uint64_t*>(g_gameBase + 0x63D1E0);
			const uint8_t mstate = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x655ECC);
			LogF("[BootTrace +%llums] timerA=%u timerB=%u q=%llX..%llX movie=%u",
				GetTickCount64() - t0, timerA, timerB,
				static_cast<unsigned long long>(qbegin), static_cast<unsigned long long>(qend), mstate);
		}
	}).detach();
}

// Fine camera control ([Camera] ini section). The launcher's camera presets
// resolve to plain floats: distance value = (1 - preset*0.5) * 200 for the
// free camera (global at base+0x6BD128; Far=0, Mid=100, Near=200) and * 300
// for the lock-on camera (base+0x6BD12C; Far=0, Mid=150, Near=300). Turn
// speed multipliers live at base+0x61141C (pad) and base+0x611418 (mouse),
// 1.0 = Normal. A watcher re-applies the overrides so settings reloads can't
// undo them. Values below the Far preset (negative) are experimental.
static int g_camFree = -9999;
static int g_camLock = -9999;
static int g_padTurnPct = -1;
static int g_mouseTurnPct = -1;
static int g_vertTurnPct = -1; // vertical axis multiplier at base+0x611C8C, shared by pad and mouse

// Dynamic FOV ([Camera] DynamicFOVPercent): the FOV patch reads its multiplier
// from a dedicated trampoline float; a fast worker widens it while the right
// stick is deflected (reading the raw stick globals) and eases it back.
static volatile float* g_fovMulPtr = nullptr;
static float g_fovBase = 1.0f;
static int g_dynFovPct = 0;
static int g_pitchFovPct = 0;

// Stick telemetry ([Diagnostics] TraceSticks=1): logs the raw camera-stick
// values 5x/second for 60s, to check the pad-to-game mapping (deadzone and
// early saturation) before designing response curves around it.
static void StartStickTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 60000)
		{
			Sleep(200);
			const int sx = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B28);
			const int sy = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B2C);
			LogF("[Stick +%llums] x=%d y=%d", GetTickCount64() - t0, sx, sy);
		}
	}).detach();
}

// Pitch telemetry ([Diagnostics] TracePitch=1): logs candidate camera-angle
// globals 5x/second for 60s. Protocol: tilt the camera slowly to max up, hold,
// then max down, hold, recenter — the address that follows is the live pitch.
static void StartPitchTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const uintptr_t addrs[] = { 0x659270, 0x6591C0, 0x6591D0, 0x6591D4, 0x6591DC, 0x6591E0 };
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 60000)
		{
			Sleep(200);
			float v[6];
			for (int i = 0; i < 6; i++)
				v[i] = *reinterpret_cast<volatile float*>(g_gameBase + addrs[i]);
			LogF("[Pitch +%llums] 270=%.4f 1C0=%.4f 1D0=%.4f 1D4=%.4f 1DC=%.4f 1E0=%.4f",
				GetTickCount64() - t0, v[0], v[1], v[2], v[3], v[4], v[5]);
		}
	}).detach();
}

// Movement telemetry ([Diagnostics] TraceMove=1): groundwork for analog
// movement speed. Logs the left stick, the controlled character's current
// mover speed, the walk-toggle tier counter (its holder object is captured
// by a hook on the L3 handler), and any change in the static per-player
// control-state block at base+0x658CE0..0x658D80. The 3-minute window starts
// only once the player actor exists (i.e. after a save is loaded).
// Protocol: stand still; tilt the left stick slightly and hold; tilt fully
// and hold; then press L3 and move at each of the three speed tiers.
static volatile uint64_t* g_moveCtxCell = nullptr;
// Ring of {caller return address, mover ptr, speed} captured by hooks on the
// two mover-speed setter sites, to find who applies the walk/run tier speeds.
static volatile uint8_t* g_spdRing = nullptr;
static bool g_dashAtCap = true;
static volatile uint32_t g_applyCount = 0; // analog watcher applySpeed calls (TraceMove)
// The character the player is actually steering. NOT [0x658CF4] (that stays at the
// original leader's channel across in-field character switches - traced): the game's own
// L3 handler 0x140273d10 takes slot = [0x740598] (when [0x74126D] or [0x740940] is set,
// else 0), entry = [0x655C10 + slot*8], channel = sbyte[entry+1].
static volatile int* g_ctlChanCell = nullptr;   // mirrored for the asm hooks
static int ReadControlledChannel()
{
	int ch = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
	const uint8_t a = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x74126D);
	const uint8_t b = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x740940);
	const int idx = (a || b) ? *reinterpret_cast<volatile int*>(g_gameBase + 0x740598) : 0;
	if (idx >= 0 && idx <= 2)
	{
		const uintptr_t e = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x655C10 + idx * 8);
		if (e) ch = *reinterpret_cast<volatile int8_t*>(e + 1);
	}
	return ch;
}
static volatile uint32_t* g_spLog = nullptr;  // speed-param write ring: [0]=seq, entries of 24 bytes at +8: param,value,chan,pc
static volatile uint32_t* g_spdHead = nullptr;

// Battle event-script "move actor" telemetry ([Diagnostics] TraceScriptMove=1).
// The battle script VM drives a boss's scripted entrance with opcodes 0xE4 and
// 0xE5 ("make the actor on channel N move for D frames"): both thunks read the
// channel from float[record+0x38] and the DURATION, authored as a FRAME COUNT,
// from float[record+0x3C]. Hooks on both thunks ring-log {tag|channel, frames}
// so the wall-clock cadence of the script can be compared between 30fps and
// 120fps - the open question being whether the VM issues the next command long
// before the previous move has finished at high framerate.
// Ring entries are 8 bytes: [0]=tag|channel, [4]=duration frames.
static volatile uint8_t* g_smRing = nullptr;
static volatile uint32_t* g_smHead = nullptr;
// Chapter-2 stair sub-boss frame-budget watchdog trace ([Diagnostics] TraceWatchdog=1):
// the battle movement steppers gate each scripted leg on a per-render-frame budget -
// counter word[actor+0xcd6] (inc every rendered frame) vs budget word[actor+0xcd8].
// With the mode-1 phase fix ON the profile advances 0.25/frame at 120fps, so a leg
// needs 4x as many render frames, but the budget still counts raw render frames and
// can time the leg out at ~25% completion; the kill zeroes [ccc]/[0x160]/[0x1a8] and
// sets cd4|=0x10. These event hooks tag every dispatcher-state entry (ccc=1/2/3), every
// leg kill (timeout vs arrival, state 1 = translation and state 3 = turn servo), and
// every run-build attempt, so a 30fps capture can be diffed against a 120fps capture to
// prove or disprove the truncation. Ring entries are 24 bytes:
// [0]=tag [4]=v0 [8]=v1 [12]=v2 [16]=v3 [20]=actor low32.
static volatile uint8_t* g_wdRing = nullptr;
static volatile uint32_t* g_wdHead = nullptr;
// counts the field action processor accepting a walk-toggle press (the real path)
static volatile uint32_t* g_toggleAcceptCell = nullptr;
// per-call-site "button check returned true" counters inside the field action
// processor fn 0x1402d9240 - one of these sites is the walk toggle
static volatile uint32_t* g_chkCells[9] = {};
// Battle AI trace ([Diagnostics] TraceBattle=1): logs every non-player actor
// (AI party members and enemies) so a boss whose AI freezes or misbehaves at
// high fps can be compared against a working 30 fps run. Per actor it records
// position, current motion ids and state, plus a change-diff over the actor
// struct to expose frame-counted AI/timer fields. Run it once at FpsCap=120
// (broken) and once at FpsCap=0 (working) and send both logs.
// Boss placement/entrance trace ([Diagnostics] TraceBossPos=1): for boss/
// leader-class actors (state [actor+0x360] low16 == 0x2019) logs candidate
// WORLD-POSITION triples + velocity + motion from spawn, WITHOUT noise-muting,
// so a frame-broken scripted spawn/entrance ("appears in wrong location and
// runs into a wall at high fps, spawns on-spot at 30fps") can be pinned by
// comparing a 120fps run to a 30fps run.
// Hardware write watch ([Diagnostics] WatchAiEvent=1): a DR0 data breakpoint on the
// AI-block event word [aib(ch)+0x1a0] of the boss (armed by the BossPos watcher once
// the 0x200B boss exists), with a vectored exception handler that records the RIP of
// every instruction writing it. Names the code that raises the "attack now" event bit
// (bit 1) that General Qator Bashtar's idle loop waits on and that stops arriving at 120fps.
static bool g_watchAiEvent = false;
static volatile uint32_t g_hwHitRip[64];
static volatile uint32_t g_hwHitCnt[64];
static volatile uint32_t g_hwHitVal[64];
static LONG CALLBACK HwWatchVEH(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && (ep->ContextRecord->Dr6 & 1))
	{
		const uint32_t rip = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
		const uint32_t val = *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(ep->ContextRecord->Dr0));
		for (int i = 0; i < 64; i++)
		{
			if (g_hwHitRip[i] == rip) { g_hwHitCnt[i]++; g_hwHitVal[i] = val; break; }
			if (g_hwHitRip[i] == 0) { g_hwHitRip[i] = rip; g_hwHitCnt[i] = 1; g_hwHitVal[i] = val; break; }
		}
		ep->ContextRecord->Dr6 = 0;
		ep->ContextRecord->EFlags |= 0x10000; // RF
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
static void ArmHwWatch(uintptr_t addr)
{
	AddVectoredExceptionHandler(1, HwWatchVEH);
	const DWORD pid = GetCurrentProcessId(), me = GetCurrentThreadId();
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) return;
	THREADENTRY32 te; te.dwSize = sizeof(te);
	int armed = 0;
	if (Thread32First(snap, &te))
		do {
			if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
			HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (!h) continue;
			if (SuspendThread(h) != (DWORD)-1)
			{
				CONTEXT ctx; memset(&ctx, 0, sizeof(ctx)); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(h, &ctx))
				{
					ctx.Dr0 = addr;
					ctx.Dr7 = (ctx.Dr7 & ~0xF0003ull) | 0x1 | (0x1 << 16) | (0x3 << 18); // L0, write, 4 bytes
					if (SetThreadContext(h, &ctx)) armed++;
				}
				ResumeThread(h);
			}
			CloseHandle(h);
		} while (Thread32Next(snap, &te));
	CloseHandle(snap);
	LogF("[HwWatch] DR0 write watch on %p armed in %d threads", (void*)addr, armed);
	std::thread([] {
		uint32_t seen[64] = {};
		for (;;)
		{
			Sleep(1000);
			for (int i = 0; i < 64; i++)
			{
				const uint32_t rip = g_hwHitRip[i];
				if (!rip) break;
				const uint32_t c = g_hwHitCnt[i];
				if (c != seen[i]) { LogF("[HwWatch] writer rip=%X hits=%u lastval=%X", rip, c, g_hwHitVal[i]); seen[i] = c; }
			}
		}
	}).detach();
}

// F10 live frame-cap toggle ([Diagnostics] FpsToggleKey=1) - see the frameratelimit patch.
static volatile float* g_fpsCapCell = nullptr;
static float g_fpsCapValue = 1.0f / 30.0f;
static void StartFpsToggleWatcher()
{
	if (!g_fpsCapCell)
		return;
	std::thread([] {
		bool at30 = false;
		LogF("[FpsToggle] F10 toggles the live frame cap %.0f <-> 30", 1.0f / g_fpsCapValue);
		for (;;)
		{
			Sleep(50);
			if (GetAsyncKeyState(VK_F10) & 1)
			{
				at30 = !at30;
				*g_fpsCapCell = at30 ? (1.0f / 30.0f) : g_fpsCapValue;
				LogF("[FpsToggle +%llu] cap now %.0f", GetTickCount64(), at30 ? 30.0f : 1.0f / g_fpsCapValue);
			}
		}
	}).detach();
}

static void StartBossPosTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG armDeadline = GetTickCount64() + 15 * 60000ULL;
		for (;;) {
			if (GetTickCount64() > armDeadline) return;
			const int pc = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
			const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (tbl && pc >= 0 && pc <= 0x41 && *reinterpret_cast<volatile uintptr_t*>(tbl + pc * 8 + 0x18))
				break;
			Sleep(200);
		}
		LogF("[BossPos] armed at framerate=%.0f", g_framerate);
		const auto rf = [](uintptr_t a) -> float { return *reinterpret_cast<volatile float*>(a); };
		struct Prev { uintptr_t mover; float x, z; };
		static Prev prev[8];
		int nprev = 0;
		const ULONGLONG t0 = GetTickCount64();
		//Long window (6 min): the interesting experiment is to shove a stuck boss
		//off the geometry it beelined into and see whether it then enters the run
		//state (mode 6), which needs time to set up in-fight.
		while (GetTickCount64() - t0 < 360000) {
			Sleep(40);
			const unsigned long long now = GetTickCount64() - t0;
			const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (!tbl) continue;
			// [Roster] once per second: EVERY actor in the channel table (any class), so the
			// visible boss can be identified even when it is not a 0x2019-class actor.
			{
				static uint32_t rosterTick = 0;
				if ((++rosterTick % 25) == 0)
					for (int ch = 0; ch <= 0x41; ch++) {
						const uintptr_t a = *reinterpret_cast<volatile uintptr_t*>(tbl + ch * 8 + 0x18);
						if (!a) continue;
						const int mi = *reinterpret_cast<volatile signed char*>(a + 0x364);
						uintptr_t mv = 0;
						if (mi >= 0 && mi < 8) mv = *reinterpret_cast<volatile uintptr_t*>(a + 0x2D0 + mi * 0x38);
						LogF("[Roster +%llu] ch=%d state=%04X mode12=%u pos=%.0f,%.0f,%.0f motion=%X hp=%u/%u f95c=%02X f95d=%02X c64=%u",
							now, ch, *reinterpret_cast<volatile uint16_t*>(a + 0x360), *reinterpret_cast<volatile uint8_t*>(a + 0x12),
							mv ? rf(mv + 0x08) : 0.f, mv ? rf(mv + 0x0c) : 0.f, mv ? rf(mv + 0x10) : 0.f,
							*reinterpret_cast<volatile uint16_t*>(a + 0x884),
							*reinterpret_cast<volatile uint32_t*>(a + 0x934), *reinterpret_cast<volatile uint32_t*>(a + 0x938),
							*reinterpret_cast<volatile uint8_t*>(a + 0x95c), *reinterpret_cast<volatile uint8_t*>(a + 0x95d),
							*reinterpret_cast<volatile uint32_t*>(a + 0xc64));
					}
			}
			for (int ch = 0; ch <= 0x41; ch++) {
				const uintptr_t a = *reinterpret_cast<volatile uintptr_t*>(tbl + ch * 8 + 0x18);
				if (!a) continue;
				{
					const uint16_t st = *reinterpret_cast<volatile uint16_t*>(a + 0x360);
					if (st != 0x2019 && st != 0x200B) continue; // boss/leader classes (0x200B = General Qator Bashtar)
					// [Diagnostics] WatchAiEvent=1: arm the DR0 write watch on this boss's AI-block
					// event word once (see ArmHwWatch)
					static bool hwArmed = false;
					if (g_watchAiEvent && !hwArmed && st == 0x200B)
					{
						const uintptr_t aitbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x658840);
						if (aitbl)
						{
							const uintptr_t aib = aitbl + static_cast<uintptr_t>(ch) * 0x5a8;
							if (*reinterpret_cast<volatile int8_t*>(aib + 8) == ch)
							{
								hwArmed = true;
								ArmHwWatch(aib + 0x1a0);
							}
						}
					}
				}
				const int mi = *reinterpret_cast<volatile signed char*>(a + 0x364);
				uintptr_t mv = 0;
				if (mi >= 0 && mi < 8) mv = *reinterpret_cast<volatile uintptr_t*>(a + 0x2D0 + mi * 0x38);
				if (!mv) continue;
				const float px = rf(mv + 0x08), py = rf(mv + 0x0c), pz = rf(mv + 0x10);   // world pos
				const float fx = rf(mv + 0x58), fy = rf(mv + 0x5c), fz = rf(mv + 0x60);   // facing dir
				const float spd = rf(mv + 0x78);                                          // speed
				const uint32_t mode = *reinterpret_cast<volatile uint32_t*>(mv + 0xa8);   // mover mode flags
				const float gdx = rf(mv + 0x18), gdy = rf(mv + 0x1c), gdz = rf(mv + 0x20); // applied per-frame delta
				const float gdmag = sqrtf(gdx * gdx + gdy * gdy + gdz * gdz);             // its magnitude
				const float dx = rf(a + 0x18), dy = rf(a + 0x1c), dz = rf(a + 0x20);      // destination
				// movement delta since last sample (actual travel direction)
				int slot = -1;
				for (int i = 0; i < nprev; i++) if (prev[i].mover == mv) { slot = i; break; }
				float mvx = 0, mvz = 0;
				if (slot >= 0) { mvx = px - prev[slot].x; mvz = pz - prev[slot].z; }
				else if (nprev < 8) { slot = nprev++; prev[slot].mover = mv; }
				if (slot >= 0) { prev[slot].x = px; prev[slot].z = pz; }
				LogF("[BossPos +%llu] ch=%d motion=%X mode=%X spd=%.2f gdelta=%.2f,%.2f,%.2f gmag=%.2f pos=%.0f,%.0f,%.0f move=%.1f,%.1f face=%.2f,%.2f,%.2f dest=%.0f,%.0f,%.0f",
					now, ch, *reinterpret_cast<volatile uint16_t*>(a + 0x884), mode, spd,
					gdx, gdy, gdz, gdmag,
					px, py, pz, mvx, mvz, fx, fy, fz, dx, dy, dz);
				// Step E (read-only): translation + turn motion-profile internals, read
				// straight from the actor struct (no asm inject). Profile is embedded at
				// actor+0x160 (translation) / actor+0x1a8 (turn); the clock steps phase
				// (+0x04), ends at duration (+0x08), writes cumulative (+0x2c) and a per-call
				// velocity (+0x30) that a mode-0 clock arm consumes directly. The evaluator
				// forms velocity = cumul - [actor+0x290] then divides by xmm9 = [actor+0xdc].
				// At 30 vs 120 this pins whether phase is scaled (0.25/frame), whether the
				// divisor is ~1, and which quantity carries the 4x walk overshoot. Active only.
				{
					const uint32_t tmode = *reinterpret_cast<volatile uint32_t*>(a + 0x160);
					const uint32_t rmode = *reinterpret_cast<volatile uint32_t*>(a + 0x1a8);
					// Bug-1 (General Qator Bashtar jams): dispatcher state ccc, the per-render-frame
					// budget watchdog counter/budget cd6/cd8 (a leg killed by timeout at 120 zeroes
					// ccc and sets cd4|=0x10), and the third profile - the time-multiplier +0x238.
					const uint32_t ccc = *reinterpret_cast<volatile uint32_t*>(a + 0xccc);
					const uint32_t smode = *reinterpret_cast<volatile uint32_t*>(a + 0x238);
					if (true) // Qator jams in the AIR with ccc/tMode/rMode possibly 0 - emit every sample so the frozen state (cd6/cd8/ccc) is captured, not just active motion
						LogF("[BossProf +%llu] ch=%d tMode=%u tPhase=%.3f tDur=%.3f cumul=%.4f vel30=%.4f fd290=%.4f vel=%.3f,%.3f,%.3f div9dc=%.4f | rMode=%u rPhase=%.3f | ccc=%u cd6=%u cd8=%u sMode=%u sPhase=%.3f",
							now, ch, tmode,
							rf(a + 0x164), rf(a + 0x168), rf(a + 0x18c), rf(a + 0x190), rf(a + 0x290),
							rf(a + 0xdc), rf(a + 0xe0), rf(a + 0xe4), rf(a + 0xdc),
							rmode, rf(a + 0x1ac),
							ccc, *reinterpret_cast<volatile uint16_t*>(a + 0xcd6),
							*reinterpret_cast<volatile uint16_t*>(a + 0xcd8), smode, rf(a + 0x23c));
				}
				// [BossAI] (General Qator Bashtar lock-on freeze): the AI action scheduler and
				// every gate in front of its countdown tick (fn 0x140194a16), sampled in ALL
				// mover modes so the R1 transition itself is captured. Scheduler: state c64
				// (0 wait / 1 issue / 2 running), flags byte c68 (bit1 running, bit4 issued),
				// countdown word c6a (-1 per RENDERED frame), reload word c6c. Tick gates: type
				// field of cfc (bits 18..25, must be 2..5), cf8&0x40, 874&2 (AI alive), and the
				// predicate 0x140026b20 = [95c]&1 && !([9b7]&2) && [a09]==0 && [a17]==0.
				// AI block (table [0x658840], stride 0x5a8, channel byte at +8): behaviour id
				// +0x550 and its flags +0x48. Globals: tick gates 0x6578F4 (!=0), 0x6579BC (==0),
				// 0x6585F0 (state-2 wait), lock-on target channel 0x658D30 (-1 none) and its
				// frame timer 0x658D34. Logged on change, plus a 1 s heartbeat.
				{
					struct AiSnap { uint32_t c64, c68, cfc, cf8, b874, pred, ccc, cd4, aid, aflags, g1, g2, g3, lockT, lockF, hp, ev0, ev8, evc; };
					static AiSnap aiPrev[0x42]; static uint8_t aiHave[0x42]; static uint32_t aiTick[0x42];
					if (ch >= 0 && ch < 0x42)
					{
						const auto r8 = [](uintptr_t p) -> uint32_t { return *reinterpret_cast<volatile uint8_t*>(p); };
						const auto r32 = [](uintptr_t p) -> uint32_t { return *reinterpret_cast<volatile uint32_t*>(p); };
						AiSnap s;
						s.c64 = r32(a + 0xc64); s.hp = r32(a + 0x934);
						s.c68 = r8(a + 0xc68) | (static_cast<uint32_t>(*reinterpret_cast<volatile uint16_t*>(a + 0xc6a)) << 8)
							| (static_cast<uint32_t>(*reinterpret_cast<volatile uint16_t*>(a + 0xc6c) & 0xFF) << 24); // flags | countdown<<8 | reload.lo<<24
						s.cfc = r32(a + 0xcfc);
						s.cf8 = r8(a + 0xcf8);
						s.b874 = r8(a + 0x874);
						s.pred = r8(a + 0x95c) | (r8(a + 0x9b7) << 8) | (r8(a + 0xa09) << 16) | (r8(a + 0xa17) << 24);
						s.ccc = r32(a + 0xccc);
						s.cd4 = r8(a + 0xcd4);
						s.aid = 0xFFFFFFFF; s.aflags = 0; s.ev0 = s.ev8 = s.evc = 0;
						{
							const uintptr_t aitbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x658840);
							if (aitbl)
							{
								const uintptr_t aib = aitbl + static_cast<uintptr_t>(ch) * 0x5a8;
								if (*reinterpret_cast<volatile int8_t*>(aib + 8) == ch)
								{
									s.aid = r8(aib + 0x550);
									s.aflags = r32(aib + 0x48);
									// script op 0x15F polls bits of these three event words (arg 0 -> +0x1ac,
									// 1 -> +0x1a0, 2 -> +0x1a8); the boss idle loop exits when one is set
									s.ev0 = r32(aib + 0x1a0); s.ev8 = r32(aib + 0x1a8); s.evc = r32(aib + 0x1ac);
								}
							}
						}
						s.g1 = r8(g_gameBase + 0x6578F4);
						s.g2 = r8(g_gameBase + 0x6579BC);
						s.g3 = r8(g_gameBase + 0x6585F0);
						s.lockT = r32(g_gameBase + 0x658D30);
						s.lockF = r32(g_gameBase + 0x658D34);
						const bool changed = !aiHave[ch] || memcmp(&s, &aiPrev[ch], sizeof(s)) != 0;
						const bool heartbeat = (++aiTick[ch] % 25) == 0;
						if (changed || heartbeat)
						{
							const int cfcType = static_cast<int>(static_cast<int32_t>(s.cfc << 6) >> 24);
							LogF("[BossAI +%llu] ch=%d%s mode=%X c64=%u c68=%02X cnt=%u reload=%u hp=%u/%u cfcType=%d cf8=%02X f874=%02X pred=%08X ccc=%u cd4=%02X | ai id=%u flags=%X ev1a0=%08X ev1a8=%08X ev1ac=%08X | g1=%u g2=%u g3=%u lockT=%d lockF=%d",
								now, ch, changed ? "" : " hb", mode,
								s.c64, s.c68 & 0xFF, (s.c68 >> 8) & 0xFFFF, (s.c68 >> 24) | (r8(a + 0xc6d) << 8),
								r32(a + 0x934), r32(a + 0x938),
								cfcType, s.cf8, s.b874, s.pred, s.ccc, s.cd4,
								s.aid, s.aflags, s.ev0, s.ev8, s.evc, s.g1, s.g2, s.g3, static_cast<int>(s.lockT), static_cast<int>(s.lockF));
						}
						aiPrev[ch] = s; aiHave[ch] = 1;
					}
				}
				// [BossDiff]: while the boss hovers/idles (mover mode==4), diff its actor struct vs
				// the previous IDLE snapshot and log changed dwords with NO muting - to catch an AI
				// timer that ticks in a healthy hover but stalls/overshoots when Qator (ch13, flying)
				// freezes in the air at 120fps (fine at 30fps). Only idle->idle diffs (the move->idle
				// transition is skipped as noise). Same TraceBossPos gate.
				{
					static uint32_t bdSnap[0x42][0xE00 / 4];
					static uint8_t  bdPrevIdle[0x42];
					static uint8_t  bdHave[0x42];
					const int BDW = 0xE00 / 4;
					if (ch >= 0 && ch < 0x42)
					{
						const bool idle = (mode == 4);
						if (idle && bdHave[ch] && bdPrevIdle[ch])
						{
							char bl[1000]; size_t bll = 0; bl[0] = 0; int bshown = 0;
							for (int o = 0; o < BDW; o++)
							{
								const uint32_t v = *reinterpret_cast<volatile uint32_t*>(a + o * 4);
								if (v == bdSnap[ch][o]) continue;
								if (bshown < 48)
								{
									const int n = snprintf(bl + bll, sizeof(bl) - bll, " %X:%X>%X", o * 4, bdSnap[ch][o], v);
									if (n > 0 && bll + static_cast<size_t>(n) < sizeof(bl) - 1) bll += n;
									bshown++;
								}
								bdSnap[ch][o] = v;
							}
							if (bll) LogF("[BossDiff +%llu] ch=%d%s", now, ch, bl);
						}
						else
						{
							for (int o = 0; o < BDW; o++) bdSnap[ch][o] = *reinterpret_cast<volatile uint32_t*>(a + o * 4);
						}
						bdPrevIdle[ch] = idle ? 1 : 0;
						bdHave[ch] = 1;
					}
				}
			}
		}
		LogF("[BossPos] trace finished");
	}).detach();
}

static void StartBattleTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const int WIN = 0xE00;          // struct window in bytes
		const int WINDW = WIN / 4;
		struct Tracked {
			uintptr_t actor;
			uint32_t prev[0xE00 / 4];
			uint8_t noise[0xE00 / 4];
			bool have;
			bool seen;
			int chan;
			int px, pz, pa, lastState;
			unsigned long long lastLine;
		};
		static Tracked tr[16];
		int nTr = 0;
		// wait until the player exists in the world
		const ULONGLONG armDeadline = GetTickCount64() + 15 * 60000ULL;
		for (;;) {
			if (GetTickCount64() > armDeadline)
				return;
			const int pc = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
			const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (tbl && pc >= 0 && pc <= 0x41 && *reinterpret_cast<volatile uintptr_t*>(tbl + pc * 8 + 0x18))
				break;
			Sleep(250);
		}
		LogF("[Battle] trace armed at framerate=%.0f (compare a 120fps run vs a 30fps run)", g_framerate);
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 300000) {
			Sleep(40);
			const unsigned long long now = GetTickCount64() - t0;
			const int pc = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
			const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (!tbl)
				continue;
			for (int i = 0; i < nTr; i++)
				tr[i].seen = false;
			for (int ch = 0; ch <= 0x41; ch++) {
				if (ch == pc)
					continue;
				const uintptr_t actor = *reinterpret_cast<volatile uintptr_t*>(tbl + ch * 8 + 0x18);
				if (!actor)
					continue;
				int idx = -1;
				for (int i = 0; i < nTr; i++)
					if (tr[i].actor == actor) { idx = i; break; }
				if (idx < 0) {
					for (int i = 0; i < nTr; i++)
						if (tr[i].actor == 0) { idx = i; break; }
					if (idx < 0) {
						if (nTr >= 16)
							continue;
						idx = nTr++;
					}
					tr[idx].actor = actor;
					tr[idx].have = false;
					memset(tr[idx].noise, 0, sizeof(tr[idx].noise));
					tr[idx].px = tr[idx].pz = tr[idx].pa = tr[idx].lastState = -1000000;
					tr[idx].lastLine = 0;
					LogF("[Battle +%llu] new actor chan=%d ptr=%p", now, ch, (void*)actor);
				}
				Tracked& T = tr[idx];
				T.seen = true;
				T.chan = ch;
				const float fx = *reinterpret_cast<volatile float*>(actor + 0x1dc);
				const float fy = *reinterpret_cast<volatile float*>(actor + 0x1e0);
				const float fz = *reinterpret_cast<volatile float*>(actor + 0x1e4);
				const int st = *reinterpret_cast<volatile uint16_t*>(actor + 0x360);
				const int a0 = *reinterpret_cast<volatile uint16_t*>(actor + 0x884);
				const int a1 = *reinterpret_cast<volatile uint16_t*>(actor + 0x88a);
				const int a2 = *reinterpret_cast<volatile uint16_t*>(actor + 0x88c);
				int spd = -1;
				const int mi = *reinterpret_cast<volatile signed char*>(actor + 0x364);
				if (mi >= 0 && mi < 8) {
					const uintptr_t mover = *reinterpret_cast<volatile uintptr_t*>(actor + 0x2D0 + mi * 0x38);
					if (mover)
						spd = static_cast<int>(*reinterpret_cast<volatile float*>(mover + 0x78) * 100.0f);
				}
				const int ix = static_cast<int>(fx), iz = static_cast<int>(fz);
				const bool changed = (ix != T.px) || (iz != T.pz) || (a0 != T.pa) || (st != T.lastState);
				if (changed || now - T.lastLine >= 1000) {
					LogF("[Battle +%llu] ch=%d pos=%.1f,%.1f,%.1f st=%X anim=%X/%X/%X spd=%d",
						now, ch, fx, fy, fz, st, a0, a1, a2, spd);
					T.px = ix; T.pz = iz; T.pa = a0; T.lastState = st; T.lastLine = now;
				}
				char line[700]; size_t ll = 0; line[0] = 0; int shown = 0;
				for (int o = 0; o < WINDW; o++) {
					const uint32_t v = *reinterpret_cast<volatile uint32_t*>(actor + o * 4);
					if (!T.have) { T.prev[o] = v; continue; }
					if (v == T.prev[o]) { T.noise[o] = 0; continue; }
					if (T.noise[o] < 250) T.noise[o]++;
					T.prev[o] = v;
					if (T.noise[o] > 4) continue;
					if (shown < 30) {
						const float fv = *reinterpret_cast<const float*>(&v);
						int n;
						if (fv > -1e6f && fv < 1e6f && (v & 0x7f800000) != 0 && (v & 0x7f800000) != 0x7f800000)
							n = snprintf(line + ll, sizeof(line) - ll, " %X=%.2f", o * 4, fv);
						else
							n = snprintf(line + ll, sizeof(line) - ll, " %X=%d", o * 4, static_cast<int>(v));
						if (n > 0 && ll + static_cast<size_t>(n) < sizeof(line) - 1) ll += n;
						shown++;
					}
				}
				if (T.have && ll)
					LogF("[Battle +%llu] ch=%d d:%s", now, ch, line);
				T.have = true;
			}
			for (int i = 0; i < nTr; i++)
				if (tr[i].actor && !tr[i].seen) {
					LogF("[Battle +%llu] actor gone chan=%d", now, tr[i].chan);
					tr[i].actor = 0;
				}
		}
		LogF("[Battle] trace finished");
	}).detach();
}

// Drains the battle-script move-command ring into the log, timestamped, so the
// issue cadence can be diffed between a 30fps and a 120fps capture.
static void StartScriptMoveTraceWatcher()
{
	if (!g_logEnabled)
		return;
	std::thread([] {
		const ULONGLONG t0 = GetTickCount64();
		uint32_t seen = 0;
		LogF("[ScriptMove] armed at framerate=%.0f (tag 0xE4/0xE5 = script move opcode)", g_framerate);
		while (GetTickCount64() - t0 < 360000)
		{
			Sleep(10);
			if (!g_smRing || !g_smHead)
				continue;
			const uint32_t head = *g_smHead;
			while (seen != head)
			{
				const uint32_t slot = seen & 0x3F;
				const uint32_t tagch = *reinterpret_cast<volatile uint32_t*>(g_smRing + slot * 8);
				const uint32_t frames = *reinterpret_cast<volatile uint32_t*>(g_smRing + slot * 8 + 4);
				LogF("[ScriptMove +%llu] op=0x%02X ch=%d frames=%u",
					GetTickCount64() - t0, 0xE4 + ((tagch >> 16) & 1), tagch & 0xFFFF, frames);
				seen++;
			}
		}
		LogF("[ScriptMove] trace finished");
	}).detach();
}

// Drains the frame-budget watchdog event ring (see g_wdRing) into the log. Each
// entry is tagged; the actor low32 is mapped back to its channel via the battle
// channel table so a 30fps capture can be diffed against a 120fps one. The key
// question: at 120fps do state-1 legs die by TIMEOUT (cd6 reaching cd8 while the
// translation phase is far below its duration = truncated at ~25%) rather than by
// ARRIVAL, and does the run state (ENTER_S2) then never appear even though the
// script keeps issuing RUN_ATTEMPTs.
static void StartWatchdogTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG t0 = GetTickCount64();
		uint32_t seen = 0;
		LogF("[Watchdog] armed at framerate=%.0f (compare a 120fps run vs a 30fps run)", g_framerate);
		while (GetTickCount64() - t0 < 360000)
		{
			Sleep(10);
			if (!g_wdRing || !g_wdHead)
				continue;
			const uint32_t head = *g_wdHead;
			while (seen != head)
			{
				const uint32_t slot = seen & 0x1FF;
				volatile uint8_t* e = g_wdRing + slot * 24;
				const uint32_t tag = *reinterpret_cast<volatile uint32_t*>(e + 0);
				const uint32_t v0 = *reinterpret_cast<volatile uint32_t*>(e + 4);
				const uint32_t v1 = *reinterpret_cast<volatile uint32_t*>(e + 8);
				const uint32_t v2 = *reinterpret_cast<volatile uint32_t*>(e + 12);
				const uint32_t v3 = *reinterpret_cast<volatile uint32_t*>(e + 16);
				const uint32_t alow = *reinterpret_cast<volatile uint32_t*>(e + 20);
				int ch = -1;
				const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
				if (tbl)
					for (int c = 0; c <= 0x41; c++)
					{
						const uintptr_t a = *reinterpret_cast<volatile uintptr_t*>(tbl + c * 8 + 0x18);
						if (a && static_cast<uint32_t>(a) == alow) { ch = c; break; }
					}
				const float f2 = *reinterpret_cast<const float*>(&v2);
				const float f3 = *reinterpret_cast<const float*>(&v3);
				const unsigned long long now = GetTickCount64() - t0;
				switch (tag)
				{
				case 1: case 2: case 3:
					LogF("[Watchdog +%llu] ch=%d ENTER_S%u trans=%X turn=%X cd6=%u cd8=%u",
						now, ch, tag, v0, v1, v2, v3);
					break;
				case 0x11:
					LogF("[Watchdog +%llu] ch=%d KILL_TIMEOUT_S1 cd6=%u cd8=%u transPhase=%.3f transDur=%.3f",
						now, ch, v0, v1, f2, f3);
					break;
				case 0x12:
					LogF("[Watchdog +%llu] ch=%d KILL_ARRIVAL_S1 cd6=%u cd8=%u transPhase=%.3f transDur=%.3f",
						now, ch, v0, v1, f2, f3);
					break;
				case 0x31:
					LogF("[Watchdog +%llu] ch=%d KILL_TIMEOUT_S3turn cd6=%u cd8=%u turnPhase=%.3f turnDur=%.3f",
						now, ch, v0, v1, f2, f3);
					break;
				case 0x32:
					LogF("[Watchdog +%llu] ch=%d KILL_ARRIVAL_S3turn cd6=%u cd8=%u turnPhase=%.3f turnDur=%.3f",
						now, ch, v0, v1, f2, f3);
					break;
				case 0x50:
					LogF("[Watchdog +%llu] ch=%d RUN_ATTEMPT authoredFrames=%u", now, ch, v0);
					break;
				case 0x60:
					LogF("[Watchdog +%llu] ch=%d AI_BEHAVIOUR id=%u flags=%02X c64=%u entry=%X", now, ch, v0, v1 & 0xFF, v2, v3);
					break;
				case 0x72:
					LogF("[Watchdog +%llu] ch=%d FLAG95C_CLEAR site=72(TakeDamage kill) hp934=%u dmgFlags=%X amount=%u caller=%X", now, ch, v0, v1, v2, v3);
					break;
				case 0x80:
					LogF("[Watchdog +%llu] ch=%d APPLY_HIT flags=%X attacker=%d caller=%X hp=%u", now, ch, v0, static_cast<int>(v1), v2, v3);
					break;
				case 0x90:
					LogF("[Script +%llu] ch=%d op=%02X pc=%X thr=%u", now, static_cast<int>(v1), v0, v2, v3);
					break;
				case 0x91:
					LogF("[Script +%llu] ch=%d PROP idx=%u val=%d pc=%X", now, static_cast<int>(v2), v0, static_cast<int>(v1), v3);
					break;
				case 0x92:
					LogF("[Script +%llu] ch=%d AITBL sub=%u val=%d pc=%X", now, static_cast<int>(v2), v0, static_cast<int>(v1), v3);
					break;
				case 0x93:
					LogF("[Script +%llu] ch=%d EVBIT word=%u bit=%u SET pc=%X", now, static_cast<int>(v2), v0, v1, v3);
					break;
				case 0x94:
					LogF("[Script +%llu] ch=%d EVBIT word=%u bit=%u clear pc=%X", now, static_cast<int>(v2), v0, v1, v3);
					break;
				case 0x95:
					LogF("[AiRaise +%llu] ch=%d kind=%u bit=%u caller=%X", now, static_cast<int>(v2), v0, v1, v3);
					break;
				case 0x96:
					LogF("[Anim +%llu] frame=%.2f rate=%.3f last=%d anim=%X player=%X", now, v0 / 256.0f, *reinterpret_cast<const float*>(&v1), static_cast<int>(v2), v3, alow);
					break;
				case 0x97:
					LogF("[AiClear +%llu] ch=%d wiping ev1a0=%08X ev1a8=%08X keep=%u", now, static_cast<int>(v3), v0, v1, v2);
					break;
				case 0x71: case 0x73: case 0x74: case 0x75: case 0x76:
					LogF("[Watchdog +%llu] ch=%d FLAG95C_CLEAR site=%X old95c=%02X step934=%u c64=%u motion=%X", now, ch, tag, v0, v1, v2, v3);
					break;
				default:
					LogF("[Watchdog +%llu] ch=%d tag=%X %X %X %X %X", now, ch, tag, v0, v1, v2, v3);
					break;
				}
				seen++;
			}
		}
		LogF("[Watchdog] trace finished");
	}).detach();
}

static void StartMoveTraceWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		const auto ReadMover = [](uintptr_t* actorOut) -> uintptr_t {
			*actorOut = 0;
			const int chan = ReadControlledChannel();
			const uintptr_t table = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (!table || chan < 0 || chan > 0x41)
				return 0;
			const uintptr_t actor = *reinterpret_cast<volatile uintptr_t*>(table + chan * 8 + 0x18);
			if (!actor)
				return 0;
			*actorOut = actor;
			const int mi = *reinterpret_cast<volatile signed char*>(actor + 0x364);
			if (mi < 0 || mi >= 8)
				return 0;
			return *reinterpret_cast<volatile uintptr_t*>(actor + 0x2D0 + mi * 0x38);
		};
		// arm only once the player is actually in the world
		const ULONGLONG armDeadline = GetTickCount64() + 15 * 60000ULL;
		uintptr_t actor = 0;
		while (GetTickCount64() < armDeadline && ReadMover(&actor) == 0)
			Sleep(250);
		LogF("[Move] trace armed (actor=%p)", (void*)actor);
		const ULONGLONG t0 = GetTickCount64();
		uint32_t prevWin[40] = {};
		bool havePrev = false;
		int prevSx = 0, prevSy = 0, prevTier = -2;
		float prevSpd = -2.0f;
		uintptr_t prevActor = 0, prevMover = 0;
		ULONGLONG lastLine = 0;
		while (GetTickCount64() - t0 < 900000)
		{
			Sleep(100);
			const ULONGLONG now = GetTickCount64() - t0;
			const int sx = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B20);
			const int sy = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B24);
			float spd = -1.0f, spdmax = -1.0f;
			const uintptr_t mover = ReadMover(&actor);
			if (mover)
			{
				spd = *reinterpret_cast<volatile float*>(mover + 0x78);
				spdmax = *reinterpret_cast<volatile float*>(mover + 0x488);
			}
			int tier = -1;
			const uint64_t ctx = g_moveCtxCell ? *g_moveCtxCell : 0;
			if (ctx)
				tier = *reinterpret_cast<volatile int*>(static_cast<uintptr_t>(ctx) + 0x170);
			uint32_t win[40];
			for (int i = 0; i < 40; i++)
				win[i] = *reinterpret_cast<volatile uint32_t*>(g_gameBase + 0x658CE0 + i * 4);
			if (actor != prevActor || mover != prevMover)
			{
				LogF("[Move +%llu] actor=%p mover=%p", now, (void*)actor, (void*)mover);
				prevActor = actor; prevMover = mover;
			}
			char delta[1024]; delta[0] = 0; size_t dl = 0;
			for (int i = 0; i < 40; i++)
			{
				if (havePrev && win[i] == prevWin[i])
					continue;
				const int n = snprintf(delta + dl, sizeof(delta) - dl, " %X=%X", 0xCE0 + i * 4, win[i]);
				if (n < 0 || dl + n >= sizeof(delta) - 1)
					break;
				dl += n;
				prevWin[i] = win[i];
			}
			// analog-speed drop hunt: the applier 0x19C960 writes [actor+0x2a8] = [0x637000]*m2
			// and [actor+0x298] = slot(29c/2a0/2a4 by move mode [0x636FF0]-7) = const*m1;
			// log the mode, the multiplier globals and the actor slots whenever the live
			// run speed +0x298 changes
			static float prevA298 = -1.0f; static int prevMode = -1;
			const int mode = *reinterpret_cast<volatile int*>(g_gameBase + 0x636FF0);
			const float m1 = *reinterpret_cast<volatile float*>(g_gameBase + 0x637004);
			const float a298 = actor ? *reinterpret_cast<volatile float*>(actor + 0x298) : -1.0f;
			const bool stickMoved = (abs(sx - prevSx) > 2) || (abs(sy - prevSy) > 2);
			if (dl || stickMoved || spd != prevSpd || tier != prevTier || a298 != prevA298 || mode != prevMode || now - lastLine >= 2000)
			{
				LogF("[Move +%llu] LS=%d,%d spd=%.3f max=%.3f tier=%d mode=%d m1=%.3f a298=%.3f slots=%.3f/%.3f/%.3f a2a8=%.3f blend=%.3f/%.3f g965=%u cap=%d m1s=%.3f applies=%u%s%s",
					now, sx, sy, spd, spdmax, tier, mode, m1, a298,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x29c) : -1.0f,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x2a0) : -1.0f,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x2a4) : -1.0f,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x2a8) : -1.0f,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x110) : -1.0f,
					actor ? *reinterpret_cast<volatile float*>(actor + 0x124) : -1.0f,
					actor ? *reinterpret_cast<volatile uint8_t*>(actor + 0x965) : 255u,
					*reinterpret_cast<volatile int*>(g_gameBase + 0x658BD8),
					*reinterpret_cast<volatile float*>(g_gameBase + 0x611E8C),
					static_cast<unsigned>(g_applyCount),
					dl ? " st:" : "", delta);
				prevSx = sx; prevSy = sy; prevSpd = spd; prevTier = tier; prevA298 = a298; prevMode = mode;
				lastLine = now;
				havePrev = true;
			}
			// [Party]: channels 0..3 every 500 ms - actor ptr, class, position, run speed and
			// the mode/const globals, to see which actor actually moves under the stick and
			// what a character switch does to channels/actors (CF4 stayed 0 across switches)
			{
				static ULONGLONG lastParty = 0;
				const uintptr_t tbl = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
				if (tbl && now - lastParty >= 500)
				{
					lastParty = now;
					char pl[900]; size_t pn = 0; pl[0] = 0;
					for (int c = 0; c < 4; c++)
					{
						const uintptr_t a = *reinterpret_cast<volatile uintptr_t*>(tbl + c * 8 + 0x18);
						if (!a) { const int n = snprintf(pl + pn, sizeof(pl) - pn, " ch%d=-", c); if (n > 0) pn += n; continue; }
						const int mi2 = *reinterpret_cast<volatile signed char*>(a + 0x364);
						uintptr_t mv2 = 0;
						if (mi2 >= 0 && mi2 < 8) mv2 = *reinterpret_cast<volatile uintptr_t*>(a + 0x2D0 + mi2 * 0x38);
						const int n = snprintf(pl + pn, sizeof(pl) - pn, " ch%d=%X cls=%04X pos=%.0f,%.0f a298=%.1f",
							c, static_cast<uint32_t>(a), *reinterpret_cast<volatile uint16_t*>(a + 0x360),
							mv2 ? *reinterpret_cast<volatile float*>(mv2 + 0x08) : 0.f, mv2 ? *reinterpret_cast<volatile float*>(mv2 + 0x10) : 0.f,
							*reinterpret_cast<volatile float*>(a + 0x298));
						if (n > 0) pn += n;
					}
					LogF("[Party +%llu] ctl=%d CE4=%u CF4=%d mode=%d c8=%.1f c9=%.1f m1=%.3f%s", now, ReadControlledChannel(),
						*reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x658CE4), *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4),
						*reinterpret_cast<volatile int*>(g_gameBase + 0x636FF0), *reinterpret_cast<volatile float*>(g_gameBase + 0x636FF8),
						*reinterpret_cast<volatile float*>(g_gameBase + 0x636FFC), *reinterpret_cast<volatile float*>(g_gameBase + 0x637004), pl);
				}
			}
			// drain the speed-param write ring (AnalogGlobalsFix hooks): who set which
			// walk/run/sprint speed (param 0 = base), value, channel, script PC
			if (g_spLog)
			{
				static uint32_t spSeen = 0;
				const uint32_t head = g_spLog[0];
				if (head - spSeen > 16) spSeen = head - 16;
				while (spSeen != head)
				{
					const volatile uint32_t* e = g_spLog + 2 + (spSeen & 15) * 6;
					LogF("[Param +%llu] ch=%d param=%u val=%.3f pc=%X", now, static_cast<int>(e[2]), e[0], *reinterpret_cast<const float*>(const_cast<const uint32_t*>(e + 1)), e[3]);
					spSeen++;
				}
			}
			// drain the SetSpeed capture ring: log each distinct caller rva, and
			// again when the (integer) speed it writes changes
			if (g_spdRing)
			{
				static uint64_t seenRva[64];
				static int seenSpd[64];
				static int seenCnt = 0;
				for (int slot = 0; slot < 32; slot++)
				{
					const uint64_t ret = *reinterpret_cast<volatile uint64_t*>(g_spdRing + slot * 24);
					const uint64_t mv = *reinterpret_cast<volatile uint64_t*>(g_spdRing + slot * 24 + 8);
					const float sv = *reinterpret_cast<volatile float*>(g_spdRing + slot * 24 + 16);
					if (!ret)
						continue;
					const uint64_t rva = ret - g_gameBase;
					const int svi = static_cast<int>(sv);
					int k = 0;
					for (; k < seenCnt; k++)
						if (seenRva[k] == rva)
							break;
					if (k < seenCnt && seenSpd[k] == svi)
						continue;
					if (k == seenCnt && seenCnt < 64)
						seenCnt++;
					if (k < 64)
					{
						seenRva[k] = rva;
						seenSpd[k] = svi;
						LogF("[SetSpd +%llu] ret=+0x%llX spd=%.3f mover=%p%s",
							now, rva, sv, (void*)mv, (mv == mover) ? " PLAYER" : "");
					}
				}
			}
		}
		LogF("[Move] trace finished");
	}).detach();
	// Fast button-state probe v5: watches the whole virtual-button pressed
	// array (base+0x658BA0, 96 ids) plus ALL 48 keyboard and 48 pad device
	// records (24 bytes each) at 125Hz, logging changed bytes. Bytes that
	// change many ticks in a row (frame counters etc) are muted after 3 ticks.
	// Also reports the walk-toggle acceptance counter so a real L3 press can
	// be matched to the exact bytes it flips.
	std::thread([] {
		Sleep(3000);
		const int r1 = *reinterpret_cast<volatile int*>(g_gameBase + 0x6115F8 + 4);
		const int r2 = *reinterpret_cast<volatile int*>(g_gameBase + 0x611638 + 8);
		const int r3 = *reinterpret_cast<volatile int*>(g_gameBase + 0x61163C + 8);
		LogF("[Btn] remaps for id1: 6115F8=%d 611638=%d 61163C=%d", r1, r2, r3);
		const int NA = 96, NK = 48 * 24, NP = 48 * 24;
		const int TOT = NA + NK + NP;
		static uint8_t prev[96 + 48 * 24 * 2];
		static uint8_t noise[96 + 48 * 24 * 2];
		memset(noise, 0, sizeof(noise));
		bool first = true;
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 300000)
		{
			Sleep(8);
			uint8_t cur[96 + 48 * 24 * 2];
			for (int i = 0; i < NA; i++)
				cur[i] = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x658BA0 + i);
			for (int i = 0; i < NK; i++)
				cur[NA + i] = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x638080 + i);
			for (int i = 0; i < NP; i++)
				cur[NA + NK + i] = *reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x638640 + i);
			{
				static uint32_t lastChk[9];
				uint32_t chk[9];
				bool moved = false;
				for (int i = 0; i < 9; i++)
				{
					chk[i] = g_chkCells[i] ? *g_chkCells[i] : 0;
					if (chk[i] != lastChk[i])
						moved = true;
				}
				if (moved)
				{
					LogF("[Btn +%llu] chk=%u,%u,%u,%u,%u,%u,%u,%u,%u", GetTickCount64() - t0,
						chk[0], chk[1], chk[2], chk[3], chk[4], chk[5], chk[6], chk[7], chk[8]);
					memcpy(lastChk, chk, sizeof(chk));
				}
			}
			if (first)
			{
				memcpy(prev, cur, TOT);
				first = false;
				continue;
			}
			char line[700]; size_t ll = 0; line[0] = 0;
			int shown = 0, hidden = 0;
			for (int i = 0; i < TOT; i++)
			{
				if (cur[i] == prev[i])
				{
					noise[i] = 0;
					continue;
				}
				if (noise[i] < 250)
					noise[i]++;
				if (noise[i] > 3)
				{
					hidden++;
					continue;
				}
				char tag[24];
				if (i < NA)
					snprintf(tag, sizeof(tag), " a%X=%u", i, cur[i]);
				else if (i < NA + NK)
					snprintf(tag, sizeof(tag), " k%X.%d=%u", (i - NA) / 24, (i - NA) % 24, cur[i]);
				else
					snprintf(tag, sizeof(tag), " p%X.%d=%u", (i - NA - NK) / 24, (i - NA - NK) % 24, cur[i]);
				const int n = snprintf(line + ll, sizeof(line) - ll, "%s", tag);
				if (n < 0 || ll + n >= sizeof(line) - 1)
					break;
				ll += n;
				if (++shown >= 40)
					break;
			}
			if (ll)
				LogF("[Btn +%llu]%s%s", GetTickCount64() - t0, line, hidden ? " (+muted)" : "");
			memcpy(prev, cur, TOT);
		}
		LogF("[Btn] probe finished");
	}).detach();
}

// Analog movement tiers ([Movement] AnalogTiers=1): the game moves at one of
// three fixed speeds cycled by the walk-toggle button (L3) and ignores how far
// the left stick is tilted. The current tier lives in the byte at
// base+0x658BD8 (0/1/2, found by memory diff against real L3 presses); this
// watcher simply writes it from the left-stick deflection, so tilt = speed
// like in modern games. While enabled, manual L3 presses are overridden.
static int g_analogTiers = 0;
static int g_tiltWalk = 80;
static int g_tiltSprint = 95;
static int g_minSpeedPct = 60;
// diagnostics: how often the hooked input check runs / runs with edx==1 /
// eats our flag, and which of the game's two other toggle-execution paths fire
static volatile uint32_t* g_walkPressCell = nullptr;
static volatile uint32_t* g_tierReachCell = nullptr;
static volatile uint32_t* g_tierExecCell = nullptr;
static volatile uint32_t* g_tierEatenCell = nullptr;
static volatile uint32_t* g_tierPathBCell = nullptr;
static volatile uint32_t* g_tierPathCCell = nullptr;
static void StartAutoTierWatcher()
{
	if (!g_analogTiers || !g_gameBase)
		return;
	std::thread([] {
		// The walk-toggle press handler (found via hardware write-watch at
		// rva +0x273Dxx) reads the multiplier row {m1,m2,m3,iconId} from the
		// table at base+0x611668 (stride 16: 1.0 / 1.5 / 2.0), stores m1 to
		// [0x611E8C] and calls the applier at base+0x19C960(actor, m1, m2,
		// m3), which just writes the multiplier globals at [0x637004..0C] and
		// the actor speed fields (+0x298..2A8, blend at +0x110/+0x124). We
		// drive the same applier from the stick: the multiplier slides
		// linearly from 1.0 to the cap as the tilt goes from WalkTilt% to
		// SprintTilt%. The handler itself is rewired (see the patch) so L3
		// toggles [0x658BD8] between 1 and 2 = the cap (1.5x or 2.0x),
		// showing the matching speed icon natively.
		using ApplySpeedFn = void(*)(uintptr_t actor, float m1, float m2, float m3);
		const auto applySpeed = reinterpret_cast<ApplySpeedFn>(g_gameBase + 0x19C960);
		uintptr_t appliedActor = 0;
		for (;;)
		{
			Sleep(16);
			uintptr_t actor = 0, mover = 0;
			const int chan = ReadControlledChannel();
			if (g_ctlChanCell) *g_ctlChanCell = chan;
			const uintptr_t table = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (table && chan >= 0 && chan <= 0x41)
			{
				actor = *reinterpret_cast<volatile uintptr_t*>(table + chan * 8 + 0x18);
				if (actor)
				{
					const int mi = *reinterpret_cast<volatile signed char*>(actor + 0x364);
					if (mi >= 0 && mi < 8)
						mover = *reinterpret_cast<volatile uintptr_t*>(actor + 0x2D0 + mi * 0x38);
				}
			}
			// leave everything alone without a live player or in cutscenes
			// (the toggle handler has the same [actor+0x965] gate)
			if (!mover || *reinterpret_cast<volatile uint8_t*>(actor + 0x965) == 1)
			{
				appliedActor = 0;
				continue;
			}
			const int sx = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B20);
			const int sy = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B24);
			float mag = sqrtf(static_cast<float>(sx * sx + sy * sy)) * 100.0f / 255.0f;
			if (mag > 100.0f)
				mag = 100.0f;
			const float lo = static_cast<float>(g_tiltWalk);
			const float hi = static_cast<float>(g_tiltSprint);
			// the (rewired) L3 toggle picks which tier row caps the analog
			// range: [0x658BD8]==2 -> the 2.0x row, anything else -> 1.5x
			const int capRow = (*reinterpret_cast<volatile int*>(g_gameBase + 0x658BD8) == 2) ? 2 : 1;
			const volatile float* rowLo = reinterpret_cast<volatile float*>(g_gameBase + 0x611668);
			const volatile float* rowHi = reinterpret_cast<volatile float*>(g_gameBase + 0x611668 + capRow * 16);
			float m1, m2, m3;
			if (mag < lo)
			{
				// below the walk threshold: from MinSpeed% at a barely-tilted
				// stick (~5%, the game's own movement deadzone) up to normal
				const float minM = g_minSpeedPct / 100.0f;
				float span0 = lo - 5.0f;
				if (span0 < 1.0f)
					span0 = 1.0f;
				float t0 = (mag - 5.0f) / span0;
				if (t0 < 0.0f) t0 = 0.0f;
				if (t0 > 1.0f) t0 = 1.0f;
				const float mm = minM + (1.0f - minM) * t0;
				m1 = rowLo[0] * mm;
				m2 = rowLo[1] * mm;
				m3 = rowLo[2] * mm;
			}
			else
			{
				float span = hi - lo;
				if (span < 1.0f)
					span = 1.0f;
				float t = (mag - lo) / span;
				if (t > 1.0f) t = 1.0f;
				m1 = rowLo[0] + (rowHi[0] - rowLo[0]) * t;
				m2 = rowLo[1] + (rowHi[1] - rowLo[1]) * t;
				m3 = rowLo[2] + (rowHi[2] - rowLo[2]) * t;
			}
			// re-apply when the target moved, the character changed, or the
			// game (or the L3 toggle) applied something else behind our back
			const float curM1 = *reinterpret_cast<volatile float*>(g_gameBase + 0x637004);
			// The applier writes the multiplier globals unconditionally but the actor's
			// speed slots ONLY when the move mode [0x636FF0] is 7..9 (walk/run/sprint);
			// a call that lands during any other mode (dash, jump, landing) updates the
			// globals and returns, and a global-only check then believes the speed is
			// applied while the actor keeps its old value - the "speed drops and sticks
			// until L3/dash" bug. Compare against the actor's expected run speed
			// (mode constant [0x636FF4 + (mode-7)*4] * m1) and never apply outside 7..9.
			const int mode = *reinterpret_cast<volatile int*>(g_gameBase + 0x636FF0);
			if (mode < 7 || mode > 9)
				continue;                       // cannot take effect now; retry next tick
			const float expect = *reinterpret_cast<volatile float*>(g_gameBase + 0x636FF4 + (mode - 7) * 4) * m1;
			const float a298 = *reinterpret_cast<volatile float*>(actor + 0x298);
			const bool actorOk = (expect > 0.0f) ? (fabsf(a298 - expect) <= 0.02f * expect) : true;
			if (fabsf(curM1 - m1) < 0.02f && actor == appliedActor && actorOk)
				continue;
			// [Movement] DashAtCap (default 1): m1 drives the run speed (+0x298 slot) and
			// follows the stick; m2 feeds [actor+0x2a8] = base*m2, which scales scripted
			// moves (dash/rush distance in 0x1401aa6bc/0x1401aa89f), and m3 the script-side
			// tier query. Keep those two at the cap row so a dash is always full speed no
			// matter how far the stick is tilted (stock rows hold m1==m2==m3 per tier).
			if (g_dashAtCap)
			{
				m2 = rowHi[1];
				m3 = rowHi[2];
			}
			*reinterpret_cast<volatile float*>(g_gameBase + 0x611E8C) = m1;
			applySpeed(actor, m1, m2, m3);
			g_applyCount++;
			appliedActor = actor;
		}
	}).detach();
}

// Write-watch ([Diagnostics] WriteWatch=1): hardware data breakpoints on the
// walk-toggle tier byte (base+0x658BD8, DR0) and its press counter
// (base+0x658BD4, DR1) on every game thread, with a vectored exception
// handler that rings the writer's RIP. A few real L3 presses reveal exactly
// which code writes the tier - and therefore where the game applies it.
static volatile uint64_t g_wwRing[64];
static volatile LONG g_wwHead = 0;
static uintptr_t g_wwAddr0 = 0, g_wwAddr1 = 0;
static LONG CALLBACK WwHandler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;
	const DWORD64 dr6 = ep->ContextRecord->Dr6;
	if (!(dr6 & 0x3))
		return EXCEPTION_CONTINUE_SEARCH;
	const uint64_t rip = ep->ContextRecord->Rip;
	const uint8_t v0 = g_wwAddr0 ? *reinterpret_cast<volatile uint8_t*>(g_wwAddr0) : 0;
	const LONG slot = (InterlockedIncrement(&g_wwHead) - 1) & 63;
	// pack: rip | value<<48 | which-breakpoint<<56
	g_wwRing[slot] = (rip & 0xFFFFFFFFFFFFull) | (static_cast<uint64_t>(v0) << 48)
		| (static_cast<uint64_t>(dr6 & 0x3) << 56);
	ep->ContextRecord->Dr6 = 0;
	ep->ContextRecord->EFlags |= 0x10000; // resume flag: don't re-trigger
	return EXCEPTION_CONTINUE_EXECUTION;
}
static void WwApplyToThreads(bool set)
{
	const DWORD self = GetCurrentThreadId();
	const DWORD pid = GetCurrentProcessId();
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return;
	THREADENTRY32 te; te.dwSize = sizeof(te);
	if (Thread32First(snap, &te))
	{
		do
		{
			if (te.th32OwnerProcessID != pid || te.th32ThreadID == self)
				continue;
			HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
			if (!h)
				continue;
			if (SuspendThread(h) != static_cast<DWORD>(-1))
			{
				CONTEXT ctx = {};
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(h, &ctx))
				{
					if (set)
					{
						ctx.Dr0 = g_wwAddr0;
						ctx.Dr1 = g_wwAddr1;
						// L0+L1 enabled, RW=write, LEN=1 byte
						ctx.Dr7 = (ctx.Dr7 & ~0xFF00FFull) | 0x5 | (0x1ull << 16) | (0x1ull << 20);
					}
					else
					{
						ctx.Dr0 = 0; ctx.Dr1 = 0;
						ctx.Dr7 &= ~0xFF00FFull;
					}
					SetThreadContext(h, &ctx);
				}
				ResumeThread(h);
			}
			CloseHandle(h);
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);
}
static void StartWriteWatch()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	g_wwAddr0 = g_gameBase + 0x658BD8;
	g_wwAddr1 = g_gameBase + 0x658BD4;
	std::thread([] {
		PVOID veh = AddVectoredExceptionHandler(1, WwHandler);
		LogF("[WW] armed: hardware write-watch on tier byte; press L3 a few times");
		const ULONGLONG t0 = GetTickCount64();
		LONG seen = 0;
		uint64_t uniq[32]; int uniqSpd[32]; int nu = 0;
		while (GetTickCount64() - t0 < 180000)
		{
			WwApplyToThreads(true); // cover newly created threads too
			for (int t = 0; t < 20; t++)
			{
				Sleep(100);
				const LONG head = g_wwHead;
				while (seen < head && seen + 64 >= head)
				{
					const uint64_t e = g_wwRing[seen & 63];
					seen++;
					const uint64_t rip = e & 0xFFFFFFFFFFFFull;
					const uint64_t rva = rip - (g_gameBase & 0xFFFFFFFFFFFFull);
					const int val = static_cast<int>((e >> 48) & 0xFF);
					const int which = static_cast<int>((e >> 56) & 0x3);
					int k = 0;
					for (; k < nu; k++)
						if (uniq[k] == rva && uniqSpd[k] == val)
							break;
					if (k < nu)
						continue;
					if (nu < 32)
					{
						uniq[nu] = rva; uniqSpd[nu] = val; nu++;
					}
					LogF("[WW +%llu] writer rip=+0x%llX dr%d newval=%d",
						GetTickCount64() - t0, rva, (which & 2) ? 1 : 0, val);
				}
				if (seen + 64 < g_wwHead)
					seen = g_wwHead; // overflow: skip ahead
			}
		}
		WwApplyToThreads(false);
		if (veh)
			RemoveVectoredExceptionHandler(veh);
		LogF("[WW] done (%ld hits)", g_wwHead);
	}).detach();
}

// Tier scan ([Diagnostics] TierScan=1): find the walk-toggle tier variable by
// diffing the whole static data region while the user presses L3 exactly 4
// times, ~4 seconds apart, standing still and touching nothing else. Reports
// bytes that changed 2..10 times, >=1.2s apart, ending on small values.
// TierScan=2: focused probe of the candidate windows found by the full scan.
// Logs every byte change together with the player's current mover speed so
// values can be matched to tiers.
static void StartTierProbeWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		struct Win { uint32_t rva, len; };
		static const Win wins[] = {
			{ 0x658BC0, 0x50 },   // input-control statics around 0x658BD5
			{ 0x750660, 0x30 },   // single 0x750677
			{ 0x7753F8, 0x20 },   // single 0x775409
			{ 0x75B298, 0x20 },   // single 0x75B2A8
			{ 0x62A590, 0x150 },  // HUD-ish cluster (icon anim?)
		};
		const int NW = sizeof(wins) / sizeof(wins[0]);
		uint8_t prev[0x50 + 0x30 + 0x20 + 0x20 + 0x150];
		int total = 0;
		for (int w = 0; w < NW; w++)
			total += wins[w].len;
		const ULONGLONG armDeadline = GetTickCount64() + 15 * 60000ULL;
		uintptr_t mover = 0;
		for (;;)
		{
			if (GetTickCount64() > armDeadline)
				return;
			const int chan = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
			const uintptr_t table = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (table && chan >= 0 && chan <= 0x41)
			{
				const uintptr_t actor = *reinterpret_cast<volatile uintptr_t*>(table + chan * 8 + 0x18);
				if (actor)
				{
					const int mi = *reinterpret_cast<volatile signed char*>(actor + 0x364);
					if (mi >= 0 && mi < 8)
						mover = *reinterpret_cast<volatile uintptr_t*>(actor + 0x2D0 + mi * 0x38);
					if (mover)
						break;
				}
			}
			Sleep(250);
		}
		int idx = 0;
		for (int w = 0; w < NW; w++)
			for (uint32_t i = 0; i < wins[w].len; i++, idx++)
				prev[idx] = *reinterpret_cast<volatile uint8_t*>(g_gameBase + wins[w].rva + i);
		LogF("[TierProbe] armed: press L3 / run / stop repeatedly");
		const ULONGLONG t0 = GetTickCount64();
		while (GetTickCount64() - t0 < 150000)
		{
			Sleep(50);
			const float spd = mover ? *reinterpret_cast<volatile float*>(mover + 0x78) : -1.0f;
			char line[600]; size_t ll = 0; line[0] = 0;
			idx = 0;
			for (int w = 0; w < NW; w++)
				for (uint32_t i = 0; i < wins[w].len; i++, idx++)
				{
					const uint8_t v = *reinterpret_cast<volatile uint8_t*>(g_gameBase + wins[w].rva + i);
					if (v == prev[idx])
						continue;
					prev[idx] = v;
					const int n = snprintf(line + ll, sizeof(line) - ll, " %X=%u", wins[w].rva + i, v);
					if (n < 0 || ll + n >= sizeof(line) - 1)
						break;
					ll += n;
				}
			if (ll)
				LogF("[TierProbe +%llu] spd=%.1f%s", GetTickCount64() - t0, spd, line);
		}
		LogF("[TierProbe] done");
	}).detach();
}

static void StartTierScanWatcher()
{
	if (!g_logEnabled || !g_gameBase)
		return;
	std::thread([] {
		// wait for the player to be in the world
		const ULONGLONG armDeadline = GetTickCount64() + 15 * 60000ULL;
		for (;;)
		{
			if (GetTickCount64() > armDeadline)
				return;
			const int chan = *reinterpret_cast<volatile int*>(g_gameBase + 0x658CF4);
			const uintptr_t table = *reinterpret_cast<volatile uintptr_t*>(g_gameBase + 0x667E20);
			if (table && chan >= 0 && chan <= 0x41 &&
				*reinterpret_cast<volatile uintptr_t*>(table + chan * 8 + 0x18))
				break;
			Sleep(250);
		}
		Sleep(2000);
		const uint32_t start_rva = 0x60B000;
		const uint32_t n = 0x3E2890;
		auto lastv = static_cast<uint8_t*>(malloc(n));
		auto lastt = static_cast<uint32_t*>(calloc(n, 4));
		auto firstt = static_cast<uint32_t*>(calloc(n, 4));
		auto cnt = static_cast<uint8_t*>(calloc(n, 1));
		auto bad = static_cast<uint8_t*>(calloc(n, 1));
		if (!lastv || !lastt || !firstt || !cnt || !bad)
			return;
		auto mem = reinterpret_cast<const volatile uint8_t*>(g_gameBase + start_rva);
		for (uint32_t i = 0; i < n; i++)
			lastv[i] = mem[i];
		LogF("[TierScan] armed: press L3 exactly 4 times ~4s apart, then wait");
		const ULONGLONG t0 = GetTickCount64();
		for (;;)
		{
			Sleep(150);
			const uint32_t now = static_cast<uint32_t>(GetTickCount64() - t0);
			if (now > 60000)
				break;
			for (uint32_t i = 0; i < n; i++)
			{
				const uint8_t v = mem[i];
				if (v == lastv[i])
					continue;
				if (v > 16)
					bad[i] = 1;
				else if (cnt[i] && now - lastt[i] < 1200)
					bad[i] = 1;
				if (!cnt[i])
					firstt[i] = now;
				if (cnt[i] < 250)
					cnt[i]++;
				lastt[i] = now;
				lastv[i] = v;
			}
		}
		auto hit = bad;
		for (uint32_t i = 0; i < n; i++)
			hit[i] = (!bad[i] && cnt[i] >= 2 && cnt[i] <= 10) ? 1 : (bad[i] = 0);
		int singles = 0, regions = 0;
		for (uint32_t i = 0; i < n; i++)
		{
			if (!hit[i])
				continue;
			uint32_t j = i;
			while (j + 1 < n)
			{
				bool more = false;
				for (uint32_t k = j + 1; k < j + 33 && k < n; k++)
					if (hit[k]) { j = k; more = true; break; }
				if (!more) break;
			}
			if (j == i)
			{
				if (singles < 80)
					LogF("[TierScan] SINGLE rva=0x%X changes=%u final=%u t=%u..%ums",
						start_rva + i, cnt[i], lastv[i], firstt[i], lastt[i]);
				singles++;
			}
			else
			{
				if (regions < 30)
					LogF("[TierScan] region 0x%X..0x%X (%u bytes)", start_rva + i, start_rva + j, j - i + 1);
				regions++;
			}
			i = j;
		}
		LogF("[TierScan] done: %d singles, %d regions", singles, regions);
	}).detach();
}

// Live-tunable knee curve state (dedicated trampoline floats, see the knee
// patch; the tuner window rewrites them when sliders move)
static volatile float* g_kneeKPtr = nullptr;
static volatile float* g_kneeCPtr = nullptr;
static volatile float* g_kneeBPtr = nullptr;
static volatile float* g_satMulPtr = nullptr;
//Below-knee segment is a polynomial c1*e + c2*e^2 + c3*e^3 so the tuner can
//blend the inner exponent live (including fractional values like 2.4)
static volatile float* g_kneeC1Ptr = nullptr;
static volatile float* g_kneeC2Ptr = nullptr;
static volatile float* g_kneeC3Ptr = nullptr;
static bool g_tuneWindow = false;

//Inner exponent p (1.0..3.0) as a blend of e^floor(p) and e^ceil(p), scaled so
//the curve still meets the knee point exactly: speed(k) = s
static void KneeInnerCoeffs(float k, float s, int expX10, float* c1, float* c2, float* c3)
{
	float p = expX10 / 10.0f;
	if (p < 1.0f) p = 1.0f;
	if (p > 3.0f) p = 3.0f;
	const int lo = (p >= 3.0f) ? 3 : static_cast<int>(p);
	const float frac = p - lo;
	float w[4] = { 0, 0, 0, 0 };
	w[lo] = 1.0f - frac;
	if (lo < 3)
		w[lo + 1] = frac;
	const float scale = s / (w[1] * k + w[2] * k * k + w[3] * k * k * k);
	*c1 = scale * w[1];
	*c2 = scale * w[2];
	*c3 = scale * w[3];
}

static void StartDynamicFovWatcher()
{
	if (!g_fovMulPtr || (g_dynFovPct <= 0 && g_pitchFovPct <= 0 && !g_tuneWindow) || !g_gameBase)
		return;
	std::thread([] {
		float cur = g_fovBase;
		//Final camera pitch in radians lives at base+0x6591D0 (traced in-game:
		//clamped to +0.471 up / -0.785 down, rest ~-0.13). Seed the limits with
		//those and keep calibrating in case other camera modes allow more.
		float calUp = 0.4712f, calDown = 0.7854f;
		for (;;)
		{
			Sleep(8);
			const int sx = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B28);
			const int sy = *reinterpret_cast<volatile int*>(g_gameBase + 0x638B2C);
			float mag = sqrtf(static_cast<float>(sx * sx + sy * sy)) / 255.0f;
			if (mag > 1.0f)
				mag = 1.0f;
			float pn = 0.0f;
			if (g_pitchFovPct > 0)
			{
				const float pitch = *reinterpret_cast<volatile float*>(g_gameBase + 0x6591D0);
				if (pitch > calUp && pitch < 1.6f)
					calUp = pitch;
				if (-pitch > calDown && -pitch < 1.6f)
					calDown = -pitch;
				pn = (pitch >= 0.0f) ? pitch / calUp : -pitch / calDown;
				if (pn > 1.0f)
					pn = 1.0f;
				pn *= pn; // quadratic: quiet near center, strong at the extremes
			}
			const float target = g_fovBase * (1.0f + g_dynFovPct / 100.0f * mag) * (1.0f + g_pitchFovPct / 100.0f * pn);
			cur += (target - cur) * 0.06f;
			*g_fovMulPtr = cur;
		}
	}).detach();
}

static void StartCameraWatcher()
{
	if ((g_camFree == -9999 && g_camLock == -9999 && g_padTurnPct < 0 && g_mouseTurnPct < 0 && g_vertTurnPct < 0 && !g_tuneWindow) || !g_gameBase)
		return;
	std::thread([] {
		for (;;)
		{
			if (g_camFree != -9999)
				*reinterpret_cast<volatile float*>(g_gameBase + 0x6BD128) = static_cast<float>(g_camFree);
			if (g_camLock != -9999)
				*reinterpret_cast<volatile float*>(g_gameBase + 0x6BD12C) = static_cast<float>(g_camLock);
			if (g_padTurnPct >= 0)
				*reinterpret_cast<volatile float*>(g_gameBase + 0x61141C) = g_padTurnPct / 100.0f;
			if (g_mouseTurnPct >= 0)
				*reinterpret_cast<volatile float*>(g_gameBase + 0x611418) = g_mouseTurnPct / 100.0f;
			if (g_vertTurnPct >= 0)
				*reinterpret_cast<volatile float*>(g_gameBase + 0x611C8C) = g_vertTurnPct / 100.0f;
			Sleep(500);
		}
	}).detach();
}

// Camera tuner window ([Camera] TuneWindow=1): a small always-on-top window
// with sliders for every live-tunable camera value plus a Save button that
// writes the current numbers back into the ini. Changes apply instantly
// (distance/speed globals via the camera watcher, knee curve via its
// dedicated trampoline floats). CurveInnerExponent still needs a restart.
struct TuneParam
{
	const wchar_t* label;
	const wchar_t* tip;
	const wchar_t* section;
	const wchar_t* iniKey;
	int minV, maxV;
	int div; // 1 = plain integer, 10 = slider holds value*10 (shown/saved with one decimal)
	volatile int* value;
};

static int g_tuneKneePos = 90, g_tuneKneeSpd = 40, g_tuneSat = 85;
static int g_tuneInnerX10 = 20, g_tuneFovPct = 0;
static TuneParam g_tuneParams[] = {
	{ L"Camera distance",
	  L"How far the camera sits from your character while exploring. Lower = farther away; negative values go beyond the launcher's \"Far\".",
	  L"Camera", L"FreeCameraDistance",       -500, 300,  1, reinterpret_cast<volatile int*>(&g_camFree) },
	{ L"Camera distance (lock-on)",
	  L"Same as above, but while locked onto an enemy.",
	  L"Camera", L"LockCameraDistance",       -500, 300,  1, reinterpret_cast<volatile int*>(&g_camLock) },
	{ L"Turn speed \x2014 pad %",
	  L"Fastest left/right camera speed on the gamepad, as % of the game's default (100 = unchanged).",
	  L"Camera", L"PadTurnSpeedPercent",        10, 300,  1, reinterpret_cast<volatile int*>(&g_padTurnPct) },
	{ L"Turn speed \x2014 mouse %",
	  L"Fastest left/right camera speed with the mouse, as % of the game's default.",
	  L"Camera", L"MouseTurnSpeedPercent",      10, 300,  1, reinterpret_cast<volatile int*>(&g_mouseTurnPct) },
	{ L"Turn speed \x2014 up/down %",
	  L"Fastest up/down camera speed (pad and mouse), as % of the game's default.",
	  L"Camera", L"VerticalTurnSpeedPercent",    5, 200,  1, reinterpret_cast<volatile int*>(&g_vertTurnPct) },
	{ L"Slow zone size %",
	  L"How much of the stick's travel stays slow and precise. Example: 90 means the first 90% of the tilt is the calm zone, and only the last 10% ramps up to full speed.",
	  L"Camera", L"CurveKneeDeflection",         5,  95,  1, reinterpret_cast<volatile int*>(&g_tuneKneePos) },
	{ L"Slow zone speed %",
	  L"Camera speed at the edge of the slow zone, as % of maximum. Lower = calmer, more precise aiming inside the zone.",
	  L"Camera", L"CurveKneeSpeed",              1,  99,  1, reinterpret_cast<volatile int*>(&g_tuneKneeSpd) },
	{ L"Start smoothness (1-3)",
	  L"How gently the camera starts moving near the stick center: 1 = even response, 3 = very soft start (tiny tilts barely move the camera). Fractions like 2.5 work.",
	  L"Camera", L"CurveInnerExponent",         10,  30, 10, reinterpret_cast<volatile int*>(&g_tuneInnerX10) },
	{ L"Full-tilt threshold %",
	  L"Stick tilt that already counts as 100%. Real pads don't reach the full range on diagonals \x2014 lowering this keeps slightly-off-axis tilts at full speed.",
	  L"Camera", L"CurveSaturation",            50, 100,  1, reinterpret_cast<volatile int*>(&g_tuneSat) },
	{ L"FOV boost when turning %",
	  L"Widens the view a little while the camera spins fast, for a modern sense of speed. 0 = off.",
	  L"Camera", L"DynamicFOVPercent",           0,  30,  1, reinterpret_cast<volatile int*>(&g_dynFovPct) },
	{ L"FOV boost looking up/down %",
	  L"Widens the view as you tilt the camera steeply up or down. 0 = off.",
	  L"Camera", L"PitchFOVPercent",             0, 100,  1, reinterpret_cast<volatile int*>(&g_pitchFovPct) },
	{ L"Field of view %",
	  L"Base field of view. 100 = the game's original.",
	  L"FOV",    L"FOVPercentage",              60, 150,  1, reinterpret_cast<volatile int*>(&g_tuneFovPct) },
};
const int TUNE_COUNT = sizeof(g_tuneParams) / sizeof(g_tuneParams[0]);
static HWND g_tuneSliders[TUNE_COUNT];
static HWND g_tuneLabels[TUNE_COUNT];
static HWND g_tuneEdits[TUNE_COUNT];

static void TuneApplyLive()
{
	if (g_kneeKPtr)
	{
		const float k = g_tuneKneePos / 100.0f;
		const float s = g_tuneKneeSpd / 100.0f;
		const float b = (1.0f - s) / (1.0f - k);
		float c = s - k * b;
		if (c > -1e-4f && c < 1e-4f)
			c = -1e-4f;
		float c1, c2, c3;
		KneeInnerCoeffs(k, s, g_tuneInnerX10, &c1, &c2, &c3);
		*g_kneeC1Ptr = c1;
		*g_kneeC2Ptr = c2;
		*g_kneeC3Ptr = c3;
		*g_kneeBPtr = b;
		*g_kneeCPtr = c;
		*g_kneeKPtr = k;
		*g_satMulPtr = 100.0f / g_tuneSat;
	}
	if (g_fovMulPtr && g_tuneFovPct > 0)
		g_fovBase = g_tuneFovPct / 100.0f; // the dynamic-FOV worker picks it up
}

static void TuneSetEditText(int i)
{
	wchar_t buf[32];
	if (g_tuneParams[i].div == 10)
		swprintf_s(buf, L"%.1f", *g_tuneParams[i].value / 10.0f);
	else
		swprintf_s(buf, L"%d", *g_tuneParams[i].value);
	SetWindowTextW(g_tuneEdits[i], buf);
}

//Typed value: parse, clamp to the slider range, apply like a slider move
static void TuneApplyEdit(int i)
{
	wchar_t buf[32];
	GetWindowTextW(g_tuneEdits[i], buf, 32);
	const float f = static_cast<float>(_wtof(buf));
	int v = static_cast<int>(f * g_tuneParams[i].div + (f >= 0 ? 0.5f : -0.5f));
	if (v < g_tuneParams[i].minV) v = g_tuneParams[i].minV;
	if (v > g_tuneParams[i].maxV) v = g_tuneParams[i].maxV;
	*g_tuneParams[i].value = v;
	SendMessageW(g_tuneSliders[i], TBM_SETPOS, TRUE, v);
	TuneApplyLive();
	TuneSetEditText(i);
}

static LRESULT CALLBACK TuneEditProc(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR ref)
{
	if (msg == WM_KEYDOWN && wp == VK_RETURN)
	{
		TuneApplyEdit(static_cast<int>(ref));
		SendMessageW(h, EM_SETSEL, 0, -1);
		return 0;
	}
	if (msg == WM_CHAR && wp == L'\r') // swallow the beep
		return 0;
	return DefSubclassProc(h, msg, wp, lp);
}

static LRESULT CALLBACK TuneWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_HSCROLL:
		for (int i = 0; i < TUNE_COUNT; i++)
		{
			if (reinterpret_cast<HWND>(lp) == g_tuneSliders[i])
			{
				*g_tuneParams[i].value = static_cast<int>(SendMessageW(g_tuneSliders[i], TBM_GETPOS, 0, 0));
				TuneSetEditText(i);
			}
		}
		TuneApplyLive();
		return 0;
	case WM_COMMAND:
		if (HIWORD(wp) == EN_KILLFOCUS && LOWORD(wp) >= 2000 && LOWORD(wp) < 2000 + TUNE_COUNT)
			TuneApplyEdit(LOWORD(wp) - 2000);
		else if (LOWORD(wp) == 1000) // Save
		{
			wchar_t buf[32];
			for (int i = 0; i < TUNE_COUNT; i++)
			{
				if (g_tuneParams[i].div == 10)
					swprintf_s(buf, L"%.1f", *g_tuneParams[i].value / 10.0f);
				else
					swprintf_s(buf, L"%d", *g_tuneParams[i].value);
				WritePrivateProfileStringW(g_tuneParams[i].section, g_tuneParams[i].iniKey, buf, wcModulePath);
			}
			SetWindowTextW(hwnd, L"FFT0HD Camera Tuner - saved!");
			LogF("[Tuner] settings saved to ini");
		}
		return 0;
	case WM_CLOSE:
		ShowWindow(hwnd, SW_MINIMIZE);
		return 0;
	}
	return DefWindowProcW(hwnd, msg, wp, lp);
}

static void StartTuneWindow()
{
	if (!g_tuneWindow)
		return;
	std::thread([] {
		INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_WIN95_CLASSES };
		InitCommonControlsEx(&icc);
		WNDCLASSW wc = {};
		wc.lpfnWndProc = TuneWndProc;
		wc.hInstance = GetModuleHandleW(nullptr);
		wc.lpszClassName = L"FFT0HDTuner";
		wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
		wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
		RegisterClassW(&wc);
		const int rowH = 52;
		HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"FFT0HDTuner", L"FFT0HD Tuner",
			WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 40, 40, 340, TUNE_COUNT * rowH + 90, nullptr, nullptr, wc.hInstance, nullptr);
		const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
		HWND tips = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, nullptr, wc.hInstance, nullptr);
		SendMessageW(tips, TTM_SETMAXTIPWIDTH, 0, 320);
		SendMessageW(tips, TTM_SETDELAYTIME, TTDT_AUTOPOP, 30000); // keep tips up long enough to read
		auto addTip = [&](HWND ctl, const wchar_t* text) {
			TOOLINFOW ti = {};
			ti.cbSize = sizeof(ti);
			ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
			ti.hwnd = hwnd;
			ti.uId = reinterpret_cast<UINT_PTR>(ctl);
			ti.lpszText = const_cast<wchar_t*>(text);
			SendMessageW(tips, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&ti));
		};
		for (int i = 0; i < TUNE_COUNT; i++)
		{
			g_tuneLabels[i] = CreateWindowExW(0, L"STATIC", g_tuneParams[i].label, WS_CHILD | WS_VISIBLE | SS_NOTIFY,
				12, 10 + i * rowH, 228, 18, hwnd, nullptr, wc.hInstance, nullptr);
			g_tuneEdits[i] = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_RIGHT,
				248, 7 + i * rowH, 68, 20, hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(2000 + i)), wc.hInstance, nullptr);
			g_tuneSliders[i] = CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | TBS_HORZ,
				8, 28 + i * rowH, 308, 22, hwnd, nullptr, wc.hInstance, nullptr);
			SendMessageW(g_tuneSliders[i], TBM_SETRANGE, TRUE, MAKELPARAM(g_tuneParams[i].minV, g_tuneParams[i].maxV));
			int v = *g_tuneParams[i].value;
			if (v < g_tuneParams[i].minV) v = g_tuneParams[i].minV;
			if (v > g_tuneParams[i].maxV) v = g_tuneParams[i].maxV;
			SendMessageW(g_tuneSliders[i], TBM_SETPOS, TRUE, v);
			SendMessageW(g_tuneLabels[i], WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
			SendMessageW(g_tuneEdits[i], WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
			SetWindowSubclass(g_tuneEdits[i], TuneEditProc, 1, i);
			TuneSetEditText(i);
			addTip(g_tuneLabels[i], g_tuneParams[i].tip);
			addTip(g_tuneSliders[i], g_tuneParams[i].tip);
			addTip(g_tuneEdits[i], g_tuneParams[i].tip);
		}
		HWND saveBtn = CreateWindowExW(0, L"BUTTON", L"Save to ini", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			90, 12 + TUNE_COUNT * rowH, 150, 30, hwnd, reinterpret_cast<HMENU>(1000), wc.hInstance, nullptr);
		SendMessageW(saveBtn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
		ShowWindow(hwnd, SW_SHOWNOACTIVATE);
		MSG m;
		while (GetMessageW(&m, nullptr, 0, 0) > 0)
		{
			TranslateMessage(&m);
			DispatchMessageW(&m);
		}
	}).detach();
}

static void PressKey(WORD vk)
{
	INPUT in = {};
	in.type = INPUT_KEYBOARD;
	in.ki.wVk = vk;
	SendInput(1, &in, sizeof(INPUT));
	Sleep(60);
	in.ki.dwFlags = KEYEVENTF_KEYUP;
	SendInput(1, &in, sizeof(INPUT));
}

static void StartBootAutoSkipWatcher()
{
	if (!g_autoSkipSplash || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG start = GetTickCount64();
		ULONGLONG lastPress = 0;
		int presses = 0;
		while (!g_bootPhaseOver)
		{
			Sleep(50);
			const ULONGLONG now = GetTickCount64();
			if (now - start > 40000)
				break;
			// any movie activity = the slides are over; stop pressing for good
			if (*reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x655ECC) != 0)
				break;
			if (now - lastPress < 200)
				continue;
			lastPress = now;
			HWND fg = GetForegroundWindow();
			DWORD pid = 0;
			if (fg)
				GetWindowThreadProcessId(fg, &pid);
			if (pid != GetCurrentProcessId())
				continue;
			PressKey(VK_RETURN);   // dismiss the autosave notice
			PressKey(VK_RSHIFT);   // Start on keyboard: skips the logo slides
			presses++;
		}
		LogF("[AutoSkip] boot auto-confirm done (%d press cycles)", presses);
	}).detach();
}

static void StartIntroSkipWatcher()
{
	if (!g_introBase)
		return;
	std::thread([] {
		int stableFor = 0;
		for (;;)
		{
			Sleep(100);
			if (*reinterpret_cast<volatile uint8_t*>(g_introBase + 0x655ECC) != 3)
			{
				stableFor = 0;
				continue;
			}
			const char* p = *reinterpret_cast<const char* volatile*>(g_introBase + 0x655EE0);
			if (!p)
				continue;
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
				continue;
			g_bootPhaseOver = 1;
			if (!IsIntroVideoPathA(p))
				continue;
			// let the player run for a few polls before skipping: arming the
			// skip in the very first ms of playback can wedge the boot flow
			if (++stableFor < 3)
				continue;
			stableFor = 0;
			LogF("[SkipIntro] skipping %hs", p);
			*reinterpret_cast<volatile uint8_t*>(g_introBase + 0x655ECD) = 1;
			*reinterpret_cast<volatile uint8_t*>(g_introBase + 0x655ECE) = 1;
			*reinterpret_cast<volatile uint8_t*>(g_introBase + 0x655ECF) = 1;
			Sleep(500);
		}
	}).detach();
}

// Movie-trace mode ([Diagnostics] TraceMovies=1): the movie system keeps its
// state machine and the current file path in globals; a watcher thread logs
// every state/path change so we can learn which files the boot logos are.
static uintptr_t g_movieBase = 0; // module base; state byte @+0x655ECC, path ptr @+0x655EE0

static void StartMovieTraceWatcher()
{
	if (!g_logEnabled || !g_movieBase)
		return;
	std::thread([] {
		const ULONGLONG start = GetTickCount64();
		uint8_t lastState = 0xFF;
		char lastPath[96] = {};
		for (;;)
		{
			Sleep(200);
			const uint8_t state = *reinterpret_cast<volatile uint8_t*>(g_movieBase + 0x655ECC);
			const char* pathptr = *reinterpret_cast<const char* volatile*>(g_movieBase + 0x655EE0);
			char path[96] = {};
			if (pathptr)
			{
				MEMORY_BASIC_INFORMATION mbi;
				if (VirtualQuery(pathptr, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
				{
					strncpy_s(path, pathptr, _TRUNCATE);
				}
			}
			if (state != lastState || strcmp(path, lastPath) != 0)
			{
				LogF("[Movie +%llums] state=%u path=%s", GetTickCount64() - start, state, path[0] ? path : "(none)");
				lastState = state;
				strcpy_s(lastPath, path);
			}
		}
	}).detach();
}

static void StartSoundTraceWatcher()
{
	if (!g_logEnabled || !g_sndRing)
		return;
	std::thread([] {
		const ULONGLONG start = GetTickCount64();
		uint32_t last = 0;
		for (;;)
		{
			Sleep(200);
			const ULONGLONG now = GetTickCount64() - start;
			if (GetAsyncKeyState(VK_F9) & 1)
				LogF("[Mark] F9 at +%llums", now);
			const uint32_t head = *g_sndHead;
			if (head != last)
			{
				char line[1024];
				int pos = 0;
				uint32_t from = (head - last > 256) ? head - 256 : last;
				for (uint32_t i = from; i != head && pos < 1000; i++)
					pos += sprintf_s(line + pos, sizeof(line) - pos, "%X ", g_sndRing[i & 0xFF]);
				LogF("[Snd +%llums] %s", now, line);
				last = head;
			}
		}
	}).detach();
}

static void StartStatsWatcher()
{
	if (!g_logEnabled || !g_stats)
		return;
	std::thread([] {
		uint32_t last[9] = {};
		const ULONGLONG start = GetTickCount64();
		for (;;)
		{
			Sleep(10000);
			uint32_t cur[9];
			for (int i = 0; i < 9; i++)
				cur[i] = *(volatile uint32_t*)&g_stats[i];
			if (memcmp(cur, last, sizeof(cur)) != 0)
			{
				LogF("[Stats +%llus] overflows: fire=%u audio=%u gameplay1=%u gameplay2=%u timings=%u layerwait=%u demowait=%u | peak slots: triggers=%u/20 counters=%u/20",
					(GetTickCount64() - start) / 1000ULL,
					cur[0], cur[1], cur[2], cur[3], cur[4], cur[7], cur[8], cur[5] + 1, cur[6] + 1);
				memcpy(last, cur, sizeof(cur));
			}
		}
	}).detach();
}

struct byte_patch {
	int32_t offset;
	uint8_t val;
};

ks_engine* ks;
ks_open_dll ks_open_fnc;
ks_asm_dll ks_asm_fnc;
ks_free_dll ks_free_fnc;
HMODULE hDLLKeystone;

constexpr float SIXTEENBYNINE = 16.0f / 9.0f;
const uint8_t ALLOCATED_FLOATS = 30;
const uint8_t CONSTANTS_ARRAY_SIZE = 5;
const uint8_t POINTERS_ARRAY_SIZE = 10;
const uint8_t FLOATS_ARRAY_SIZE = 10;

Trampoline* trampoline;
float* floatpointers;
uint64_t constants[CONSTANTS_ARRAY_SIZE]; //marked in ASM with $x
float param_floats[FLOATS_ARRAY_SIZE]; //marked in ASM with %x
uintptr_t pointers[POINTERS_ARRAY_SIZE]; //marked in ASM with ?x

//0.0f is not an acceptable value, if you need it you're probably doing something wrong (use XORPS if you need to reset a xmm register)
uintptr_t FindOrInsertFloat(float value)
{
	for (int i = 0; i < ALLOCATED_FLOATS; i++)
	{
		if (floatpointers[i] == 0.0f)
			floatpointers[i] = value;
		if (floatpointers[i] == value)
			return reinterpret_cast<uintptr_t>(&floatpointers[i]);
	}
	return NULL;
}

float DecreaseFloatPrecision(float input, uint8_t nbits)
{
	if (nbits == 0)
		return input;
	uint32_t mask = 0xFFFFFFFF - (static_cast<uint32_t>(pow(2, nbits) - 1));
	uint32_t temp = *reinterpret_cast<uint32_t*>(&input); //Necessary evil bithack that decreases the float's precision. (Only 60 and 120 fps will be 100% correct, every other value will be lower, resulting in a slight speedup or slowdown depending on context)
	temp = temp & mask;
	return *reinterpret_cast<float*>(&temp);
}

int ParametricASMJump(const char* asmstring, hook::pattern_match match, int32_t matchoffset, int32_t jumpbackoffset, byte_patch* rawpatch = nullptr, int32_t rawpatchsize = 0)
{
	size_t count;
	unsigned char* encode;
	std::byte* space;
	uintptr_t totalpointers[POINTERS_ARRAY_SIZE + FLOATS_ARRAY_SIZE]; //Floats gets resolved to a rip offsetted pointer anyway, so create a full list
	size_t relativeoffset = 0;
	size_t size;

	memcpy(totalpointers, pointers, POINTERS_ARRAY_SIZE * sizeof(uintptr_t));

	std::string replace_constants = asmstring;
	for (int i = 0; i < CONSTANTS_ARRAY_SIZE; i++) {
		std::regex e("\\$" + std::to_string(i));
		uint64_t rep = constants[i];
		replace_constants = std::regex_replace(replace_constants, e, std::to_string(constants[i])); //Replace constants via regex replace, so there is no need to worry about sizes of the constant itself
	}

	std::string replace_floats = replace_constants;
	std::smatch sm;
	for (int i = 0; i < FLOATS_ARRAY_SIZE; i++) {
		std::regex e("%" + std::to_string(i));
		totalpointers[POINTERS_ARRAY_SIZE + i] = FindOrInsertFloat(param_floats[i]); //Find the float addresses
		replace_floats = std::regex_replace(replace_floats, e, "dword ptr [rip + ?" + std::to_string(POINTERS_ARRAY_SIZE + i) + "]"); //Recreate the rip offset syntax, with range outside of what could be used so it doesn't interfere with user defined ones
	}

	std::istringstream stream(replace_floats);
	std::string s;
	std::string finaloutput = "";
	std::regex x86_jumps("J[A-Z]+[ ]+[A-Z]", std::regex_constants::icase); //A relative crude way to detect "jmp A", "je B", "jb C" etc
	std::regex ripoffset("\\?([0-9]+)");

	//Assemble all instructions separately, so we can get their size and compute the pointers offsets correctly
	while (std::getline(stream, s, ';'))
	{
		if (std::regex_search(s, sm, x86_jumps))
		{
			relativeoffset += 2; //Assume the things we patch are small enough so that there aren't 16 bits jumps
			finaloutput += s + ";";
		}
		else
		{
			if (!std::regex_search(s, sm, ripoffset))
			{
				if (ks_asm_fnc(ks, s.c_str(), 0, &encode, &size, &count))
				{
#ifdef DEBUG
					DebugBreak();
					const char* instruction = s.c_str();
#endif
					LogF("  [ASM FAIL] instruction: %s", s.c_str());
					return 1;
				}
				relativeoffset += size;
				finaloutput += s + ";";
				ks_free_fnc(encode);
			}
			else
			{
				if (ks_asm_fnc(ks, std::regex_replace(s, ripoffset, "0x11223344").c_str(), 0, &encode, &size, &count))
				{
#ifdef DEBUG
					DebugBreak();
					const char* instruction = std::regex_replace(s, ripoffset, "0x11223344").c_str();
#endif
					LogF("  [ASM FAIL] rip instruction: %s", s.c_str());
					return 1;
				}
				relativeoffset += size;
				uint64_t ripoffset_val = totalpointers[std::stoi(sm[1].str())] - (reinterpret_cast<uintptr_t>(trampoline->RawSpace(0)) + relativeoffset); //sm[1] because $0 of a regexp is the entire matched thing
				//If it's a Call near relative instruction, the offset is relative to the NEXT instruction
				if (encode[0] == 0xE8)
				{
					ripoffset_val += size;
				}
				finaloutput += std::regex_replace(s, ripoffset, std::to_string(ripoffset_val)) + ";";
				ks_free_fnc(encode);
			}
		}
	}

	if (ks_asm_fnc(ks, (finaloutput + "jmp 0x1000000;").c_str(), 0, &encode, &size, &count))
	{
#ifdef DEBUG
		DebugBreak();
		const char* full_asm_out = finaloutput.c_str();
#endif
		LogF("  [ASM FAIL] full block: %s", finaloutput.c_str());
		return 1;
	}
	space = trampoline->RawSpace(size);
	memcpy(space, encode, size);
	WriteOffsetValue(space + size - 4, match.get<void>(jumpbackoffset)); //Fill the final jump with the correct address

	//When there is a need for post assembly patching
	if (rawpatch != nullptr && rawpatchsize > 0)
	{
		for (int i = 0; i < rawpatchsize; i++)
		{
			Patch<uint8_t>(space + rawpatch[i].offset, rawpatch[i].val);
		}
	}

	InjectHook(match.get<void>(matchoffset), space, PATCH_JUMP);
	ks_free_fnc(encode);
	return 0;
}

//This defines a spline that interpolates the original "FF F0 C0 B0 A0 80 70 60" sequence of bytes used when defining the pulsating transparency (in a 0.0 -> 1.0 range)
uint8_t TransparencySplineInterpolation(float x)
{
	if (x < 0.14)
		return round(-3785.14 * pow(x, 3) - 27.75 * x + 255);
	if (x < 0.29)
		return round(7606.68 * pow(x, 3) - 4882.21 * pow(x, 2) + 669.71 * x + 221.79);
	if (x < 0.43)
		return round(-4346.59 * pow(x, 3) + 5363.45 * pow(x, 2) - 2257.63 * x + 500.58);
	if (x < 0.57)
		return round(-1196.32 * pow(x, 3) + 1313.1 * pow(x, 2) - 521.76 * x + 252.6);
	if (x < 0.71)
		return round(3643.86 * pow(x, 3) - 6984.34 * pow(x, 2) + 4219.64 * x - 650.52);
	if (x < 0.86)
		return round(-2403.12 * pow(x, 3) + 5973.47 * pow(x, 2) - 5035.95 * x + 1553.19);
	else return round(480.62 * pow(x, 3) - 1441.87 * pow(x, 2) + 1320.06 * x - 262.82);
}

//Honestly, I have no idea why Square Enix thought that the blinking yellow arrow should have different values when in battle, but here we are (a spline for this doesn't produce a great result)
uint8_t TransparencyLinearInterpolation(float x) {
	if (x < 0.52)
		return round(432.69 * x + 25);
	if (x < 0.68)
		return 250;
	else return round(-703.125 * x + 728.125);
}

void OnInitializeHook()
{

	GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
	PathRenameExtensionW(wcModulePath, L".ini");

	// Diagnostics log lives next to the .ini as "<mod>.log". Enabled by default;
	// set [Diagnostics] EnableLog=0 in the .ini to turn it off.
	lstrcpyW(wcLogPath, wcModulePath);
	PathRenameExtensionW(wcLogPath, L".log");
	g_logEnabled = GetPrivateProfileIntW(L"Diagnostics", L"EnableLog", 1, wcModulePath) != 0;
	LogInit();
	LogF("=== FFT0HD Unlocker init ===");

	g_traceFiles = GetPrivateProfileIntW(L"Diagnostics", L"TraceFiles", 0, wcModulePath) != 0;
	g_skipIntroVideos = GetPrivateProfileIntW(L"Intro", L"SkipIntroVideos", 0, wcModulePath) != 0;
	if (g_traceFiles || g_skipIntroVideos)
	{
		g_fileHookStart = GetTickCount64();
		PatchIAT("CreateFileW", HookedCreateFileW, reinterpret_cast<void**>(&g_origCreateFileW));
		PatchIAT("CreateFileA", HookedCreateFileA, reinterpret_cast<void**>(&g_origCreateFileA));
		LogF("[FileHook] CreateFileW=%s CreateFileA=%s traceFiles=%d skipIntroVideos=%d",
			g_origCreateFileW ? "hooked" : "NOT FOUND", g_origCreateFileA ? "hooked" : "NOT FOUND",
			g_traceFiles ? 1 : 0, g_skipIntroVideos ? 1 : 0);
		if (!g_origCreateFileW)
			g_traceFiles = g_skipIntroVideos = false;
	}

	hDLLKeystone = LoadLibrary(L"keystone.dll");

	ks_open_fnc = (ks_open_dll)GetProcAddress(hDLLKeystone, "ks_open");
	ks_asm_fnc = (ks_asm_dll)GetProcAddress(hDLLKeystone, "ks_asm");
	ks_free_fnc = (ks_free_dll)GetProcAddress(hDLLKeystone, "ks_free");

	if (ks_open_fnc && ks_asm_fnc && ks_free_fnc)
	{
		try
		{

		ks_open_fnc(KS_ARCH_X86, KS_MODE_64, &ks);

		trampoline = Trampoline::MakeTrampoline(GetModuleHandle(nullptr));
		uintptr_t baseaddress = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

		floatpointers = reinterpret_cast<float*>(trampoline->RawSpace(ALLOCATED_FLOATS * sizeof(float)));
		memset(floatpointers, 0, ALLOCATED_FLOATS * sizeof(float));

		// Placeholder match; every feature block reassigns this before use.
		// (Was pattern("").get_one(), which is itself an out-of-bounds read.)
		hook::pattern_match match(nullptr);

		// Optional: dump the decrypted, loaded game image to "<mod>_image.bin"
		// for offline static analysis. The on-disk exe has an encrypted .text
		// (SteamStub), so signatures only exist in memory after unpacking.
		// Dumped here, before any patch is applied, so the code is pristine.
		if (GetPrivateProfileIntW(L"Diagnostics", L"DumpImage", 0, wcModulePath) != 0)
		{
			auto imgbase = reinterpret_cast<const uint8_t*>(baseaddress);
			const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(imgbase);
			const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(imgbase + dos->e_lfanew);
			const DWORD imgsize = nt->OptionalHeader.SizeOfImage;
			wchar_t dumpPath[MAX_PATH];
			lstrcpyW(dumpPath, wcModulePath);
			PathRenameExtensionW(dumpPath, L".bin");
			FILE* df = nullptr;
			if (_wfopen_s(&df, dumpPath, L"wb") == 0 && df)
			{
				fwrite(imgbase, 1, imgsize, df);
				fclose(df);
				LogF("[DumpImage] wrote %u bytes of loaded image at base %p", imgsize, (void*)baseaddress);
			}
			else
				LogF("[DumpImage] failed to open dump file");
		}

		// Sound tracing for hunting frame-counted gameplay windows (Kill Sight etc):
		// hooks the central sound-request function and rings every sound id.
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceSounds", 0, wcModulePath) != 0)
		{
			LogF("[TraceSounds] enabled: logging sound ids, press F9 in-game to drop a marker");
			auto sndring = reinterpret_cast<uint32_t*>(trampoline->RawSpace(257 * sizeof(uint32_t)));
			memset(sndring, 0, 257 * sizeof(uint32_t));
			g_sndRing = sndring;
			g_sndHead = &sndring[256];
			match = FindOne("48 8B C4 44 89 40 18 89 50 10 48 89 48 08 53 56 57 41 54 41 55 48 81 EC C0 00 00 00");
			pointers[0] = reinterpret_cast<uintptr_t>(sndring);
			pointers[1] = reinterpret_cast<uintptr_t>(&sndring[256]);
			ParametricASMJump("push rax; push rbx; mov eax, dword ptr [rip + ?1]; mov ebx, eax; inc eax; mov dword ptr [rip + ?1], eax; and ebx, 0xff; lea rax, [rip + ?0]; mov dword ptr [rax + rbx * 4], r8d; pop rbx; pop rax; mov rax, rsp; mov dword ptr [rax + 0x18], r8d", match, 0, 0x7);
		}

		// Battle event-script "move actor" telemetry ([Diagnostics] TraceScriptMove=1).
		// Hooks the two script-VM opcodes that command an actor to move (0xE4 at
		// 0x3633B0, 0xE5 at 0x3633E0). Both are thunks that read channel from
		// float[rax+0x38] and a FRAME-COUNT duration from float[rax+0x3C], then tail-jmp
		// to the handler. We replace those two cvttss2si (11 bytes, nothing branches
		// into them) with the same two conversions plus a ring-log. r10/r11 are
		// volatile scratch and are not argument registers, so clobbering them across
		// the tail jump is safe; rax/rcx/rdx/r8 are left exactly as the handler expects.
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceScriptMove", 0, wcModulePath) != 0)
		{
			auto smring = reinterpret_cast<uint8_t*>(trampoline->RawSpace(64 * 8));
			memset(smring, 0, 64 * 8);
			auto smhead = trampoline->Pointer<uint32_t>();
			*smhead = 0;
			g_smRing = smring;
			g_smHead = smhead;
			static const char* kSmAsm =
				"cvttss2si r8d, dword ptr [rax + 0x3c]; cvttss2si edx, dword ptr [rax + 0x38]; "
				"mov r10d, dword ptr [rip + ?1]; lea r11, [rip + ?0]; inc dword ptr [rip + ?1]; "
				"and r10d, 0x3f; shl r10d, 3; "
				"mov dword ptr [r11 + r10 * 1], edx; or dword ptr [r11 + r10 * 1], $0; "
				"mov dword ptr [r11 + r10 * 1 + 4], r8d";
			// opcode 0xE5
			match = FindOne("48 8B C1 48 8B 0D ? ? ? ? 48 85 C9 74 10 F3 44 0F 2C 40 3C F3 0F 2C 50 38 E9 01 97 E4 FF");
			pointers[0] = reinterpret_cast<uintptr_t>(smring);
			pointers[1] = reinterpret_cast<uintptr_t>(smhead);
			constants[0] = 0x10000;
			ParametricASMJump(kSmAsm, match, 0x0F, 0x1A);
			// opcode 0xE4
			match = FindOne("48 8B C1 48 8B 0D ? ? ? ? 48 85 C9 74 10 F3 44 0F 2C 40 3C F3 0F 2C 50 38 E9 81 98 E4 FF");
			pointers[0] = reinterpret_cast<uintptr_t>(smring);
			pointers[1] = reinterpret_cast<uintptr_t>(smhead);
			constants[0] = 0;
			ParametricASMJump(kSmAsm, match, 0x0F, 0x1A);
			LogF("[ScriptMove] hooks installed on battle script move opcodes 0xE4/0xE5");
		}

		// Movement telemetry: capture the player-control object at the walk-toggle
		// (L3) handler so the movement trace can watch the speed-tier counter live.
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceMove", 0, wcModulePath) != 0)
		{
			auto pctx = trampoline->Pointer<uint64_t>();
			*pctx = 0;
			g_moveCtxCell = pctx;
			match = FindOne("FF 86 70 01 00 00 80 66 45 FC");
			pointers[0] = reinterpret_cast<uintptr_t>(pctx);
			ParametricASMJump("mov qword ptr [rip + ?0], rsi; inc dword ptr [rsi + 0x170]; and byte ptr [rsi + 0x45], 0xFC", match, 0, 0xA);

			// Hook the two mover-speed setter sites and ring-log the caller's
			// return address + the speed value, to locate the tier-speed code.
			auto spdring = reinterpret_cast<uint8_t*>(trampoline->RawSpace(32 * 24));
			memset(spdring, 0, 32 * 24);
			auto spdhead = trampoline->Pointer<uint32_t>();
			*spdhead = 0;
			g_spdRing = spdring;
			g_spdHead = spdhead;
			// virtual Mover::SetSpeed (mover in rcx)
			match = FindOne("83 A1 A8 00 00 00 F7 F3 0F 11 49 78 C3");
			pointers[0] = reinterpret_cast<uintptr_t>(spdring);
			pointers[1] = reinterpret_cast<uintptr_t>(spdhead);
			ParametricASMJump("push rbx; mov eax, dword ptr [rip + ?1]; mov ebx, eax; inc eax; mov dword ptr [rip + ?1], eax; and ebx, 0x1f; imul ebx, ebx, 24; lea rax, [rip + ?0]; add rax, rbx; mov rbx, qword ptr [rsp + 8]; mov qword ptr [rax], rbx; mov qword ptr [rax + 8], rcx; movss dword ptr [rax + 0x10], xmm1; pop rbx; and dword ptr [rcx + 0xA8], 0xFFFFFFF7; movss dword ptr [rcx + 0x78], xmm1", match, 0, 0xC);
			// inlined actor-level copy (mover in rdx)
			match = FindOne("83 A2 A8 00 00 00 F7 F3 0F 11 4A 78");
			pointers[0] = reinterpret_cast<uintptr_t>(spdring);
			pointers[1] = reinterpret_cast<uintptr_t>(spdhead);
			ParametricASMJump("push rbx; mov eax, dword ptr [rip + ?1]; mov ebx, eax; inc eax; mov dword ptr [rip + ?1], eax; and ebx, 0x1f; imul ebx, ebx, 24; lea rax, [rip + ?0]; add rax, rbx; mov rbx, qword ptr [rsp + 8]; mov qword ptr [rax], rbx; mov qword ptr [rax + 8], rdx; movss dword ptr [rax + 0x10], xmm1; pop rbx; and dword ptr [rdx + 0xA8], 0xFFFFFFF7; movss dword ptr [rdx + 0x78], xmm1", match, 0, 0xC);

			// wrap every button-check call site inside the field action
			// processor: count each one that returns true - the site whose
			// counter moves on a real L3 press is the walk toggle
			static const char* chkSigs[9] = {
				"E8 1E 85 F9 FF", "E8 67 84 F9 FF", "E8 12 8E F9 FF",
				"E8 A6 83 F9 FF", "E8 76 8D F9 FF", "E8 B2 82 F9 FF",
				"E8 F6 81 F9 FF", "E8 C6 8B F9 FF", "E8 13 8B F9 FF" };
			static const uint32_t chkTgt[9] = {
				0x271830, 0x271830, 0x272250, 0x271830, 0x272250,
				0x271830, 0x271830, 0x272250, 0x272250 };
			for (int i = 0; i < 9; i++)
			{
				auto c = trampoline->Pointer<uint32_t>();
				*c = 0;
				g_chkCells[i] = c;
				match = FindOne(chkSigs[i]);
				pointers[0] = reinterpret_cast<uintptr_t>(c);
				pointers[1] = baseaddress + chkTgt[i];
				ParametricASMJump("call ?1; test al, al; je A; inc dword ptr [rip + ?0]; A: nop", match, 0, 0x5);
			}
			LogF("[TraceMove] enabled: context capture + speed ring + 9 check-site counters");
		}

		// Chapter-2 stair sub-boss frame-budget watchdog trace ([Diagnostics] TraceWatchdog=1).
		// See the g_wdRing comment for the mechanism. Installs 8 event hooks - three
		// dispatcher-state entries (ccc=1/2/3), four leg kills tagged timeout-vs-arrival
		// for state 1 (translation) and state 3 (turn servo), and the run-build attempt -
		// each writing a 24-byte ring, then starts the watcher that drains it. Every hook
		// filters to the boss/leader actor (word[actor+0x360]==0x2019) and re-executes the
		// exact instruction it displaced; rax/r10/r11/flags are saved and restored so
		// injecting mid-stepper is safe. All signatures were verified unique and byte-exact
		// against the module image, and every asm block was test-assembled with keystone.
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceWatchdog", 0, wcModulePath) != 0)
		{
			auto wdring = reinterpret_cast<uint8_t*>(trampoline->RawSpace(512 * 24));
			memset(wdring, 0, 512 * 24);
			auto wdhead = trampoline->Pointer<uint32_t>();
			*wdhead = 0;
			g_wdRing = wdring;
			g_wdHead = wdhead;
			pointers[0] = reinterpret_cast<uintptr_t>(wdring);
			pointers[1] = reinterpret_cast<uintptr_t>(wdhead);

			// rbx=actor prologue: filter to boss, reserve a 24-byte slot, write tag($0) and
			// actor low32 (ebx), leave r11=&entry. Label A is the not-boss skip target.
			const std::string P =
				"push rax; push r10; push r11; pushfq; "
				"movzx r11d, word ptr [rbx + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
				"lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], ebx; ";
			const std::string EPI = "A: popfq; pop r11; pop r10; pop rax; ";
			// state entry: v0=translation profile mode[0x160], v1=turn mode[0x1a8], v2=cd6, v3=cd8
			const std::string payEnter =
				"mov eax, dword ptr [rbx + 0x160]; mov dword ptr [r11 + 4], eax; "
				"mov eax, dword ptr [rbx + 0x1a8]; mov dword ptr [r11 + 8], eax; "
				"movzx eax, word ptr [rbx + 0xcd6]; mov dword ptr [r11 + 12], eax; "
				"movzx eax, word ptr [rbx + 0xcd8]; mov dword ptr [r11 + 16], eax; ";
			// leg kill: v0=cd6, v1=cd8, v2=profile phase, v3=profile duration (raw f32 bits)
			auto payKill = [](const char* poff, const char* doff) {
				return "movzx eax, word ptr [rbx + 0xcd6]; mov dword ptr [r11 + 4], eax; "
					   "movzx eax, word ptr [rbx + 0xcd8]; mov dword ptr [r11 + 8], eax; "
					   "mov eax, dword ptr [rbx + " + std::string(poff) + "]; mov dword ptr [r11 + 12], eax; "
					   "mov eax, dword ptr [rbx + " + doff + "]; mov dword ptr [r11 + 16], eax; ";
			};

			// --- dispatcher-state entries (tag = state number) ---
			constants[0] = 1;
			match = FindOne("C7 83 CC 0C 00 00 01 00 00 00");
			ParametricASMJump((P + payEnter + EPI + "mov dword ptr [rbx + 0xccc], 1").c_str(), match, 0, 0xA);
			constants[0] = 2;
			match = FindOne("C7 83 CC 0C 00 00 02 00 00 00");
			ParametricASMJump((P + payEnter + EPI + "mov dword ptr [rbx + 0xccc], 2").c_str(), match, 0, 0xA);
			constants[0] = 3;
			match = FindOne("C7 83 CC 0C 00 00 03 00 00 00");
			ParametricASMJump((P + payEnter + EPI + "mov dword ptr [rbx + 0xccc], 3").c_str(), match, 0, 0xA);

			// --- state-1 leg kills (translation profile +0x160/phase+0x164/dur+0x168) ---
			// signatures anchored on the preceding cmp[ccc]/je so the byte-identical timeout
			// and arrival kill blocks are told apart by the je displacement (0x19 vs 0x1f);
			// inject at the 'or byte[rbx+0xcd4],0x10' and re-execute it.
			constants[0] = 0x11; // KILL_TIMEOUT_S1
			match = FindOne("21 39 B3 CC 0C 00 00 74 19 80 8B D4 0C 00 00 10");
			ParametricASMJump((P + payKill("0x164", "0x168") + EPI + "or byte ptr [rbx + 0xcd4], 0x10").c_str(), match, 0x9, 0x10);
			constants[0] = 0x12; // KILL_ARRIVAL_S1
			match = FindOne("B3 CC 0C 00 00 74 1F 80 8B D4 0C 00 00 10");
			ParametricASMJump((P + payKill("0x164", "0x168") + EPI + "or byte ptr [rbx + 0xcd4], 0x10").c_str(), match, 0x7, 0xE);

			// --- state-3 servo kills (turn profile +0x1a8/phase+0x1ac/dur+0x1b0) ---
			constants[0] = 0x31; // KILL_TIMEOUT_S3
			match = FindOne("AB CC 0C 00 00 74 19 80 8B D4 0C 00 00 10");
			ParametricASMJump((P + payKill("0x1ac", "0x1b0") + EPI + "or byte ptr [rbx + 0xcd4], 0x10").c_str(), match, 0x7, 0xE);
			constants[0] = 0x32; // KILL_ARRIVAL_S3
			match = FindOne("AB CC 0C 00 00 74 1F 80 8B D4 0C 00 00 10");
			ParametricASMJump((P + payKill("0x1ac", "0x1b0") + EPI + "or byte ptr [rbx + 0xcd4], 0x10").c_str(), match, 0x7, 0xE);

			// --- run-build attempt (builder entry; rcx=actor, r8d=authored frame count) ---
			// separate prologue: filter on rcx, store rcx low32, log r8d, re-execute the
			// displaced 'mov [rsp+0x18], rbx' prologue store.
			constants[0] = 0x50; // RUN_ATTEMPT
			match = FindOne("48 89 5C 24 18 56 57 41 56 48 81 EC F0 00 00 00 48 8B D9 48 8B 49 08");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; "
				"movzx r11d, word ptr [rcx + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
				"lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], ecx; "
				"mov dword ptr [r11 + 4], r8d; mov dword ptr [r11 + 8], 0; mov dword ptr [r11 + 12], 0; mov dword ptr [r11 + 16], 0; "
				"A: popfq; pop r11; pop r10; pop rax; "
				"mov qword ptr [rsp + 0x18], rbx", match, 0, 0x5);

			// --- AI behaviour issue (General Qator Bashtar lock-on freeze) ---
			// 0x14027eb20 is the AI branch taken when the action-decide fn 0x140193dd4
			// hands it a flags byte (bit built from "player lock-on target == my
			// channel", read from [0x658D30]); it picks a behaviour via 0x140280ba0 and
			// stores its id at [aiBlock+0x550] (rbx = AI block, rdi = actor, rsi = entry,
			// flags byte saved at [rsp+0x6c] before our 4 pushes -> [rsp+0x8c]).
			// v0 = behaviour id (al), v1 = flags byte, v2 = scheduler state [actor+0xc64],
			// v3 = entry id word[rsi]. Re-executes the displaced 6-byte store.
			constants[0] = 0x60; // AI_BEHAVIOUR
			match = FindOne("88 83 50 05 00 00 3C FF 74 0B 0F B7 16 48 8B CF");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; "
				"movzx r11d, word ptr [rdi + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
				"lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], edi; "
				"movzx eax, al; mov dword ptr [r11 + 4], eax; "
				"mov eax, dword ptr [rsp + 0x8c]; mov dword ptr [r11 + 8], eax; "
				"mov eax, dword ptr [rdi + 0xc64]; mov dword ptr [r11 + 12], eax; "
				"movzx eax, word ptr [rsi]; mov dword ptr [r11 + 16], eax; "
				"A: popfq; pop r11; pop r10; pop rax; "
				"mov byte ptr [rbx + 0x550], al", match, 0, 0x6);

			// --- [actor+0x95c] bit-0 clears (Qator freeze) ---
			// The AI tick 0x140194a16 is gated by predicate 0x140026b20, whose first test is
			// [actor+0x95c]&1. The 120fps trace showed that bit dropping (0x0D->0x8C) on both
			// boss actors mid-fight, after which the scheduler sits in state 1 forever. Six
			// code sites clear it; tag each one so the log names the culprit. v0 = old
			// byte 0x95c, v1 = action-step [0x934], v2 = scheduler state [0xc64], v3 = motion
			// id word[0x7f0]. Each re-executes its own displaced 'and byte [reg+0x95c],0xfe'.
			{
				struct ClrSite { const char* sig; const char* reg; const char* low; uint32_t tag; uint32_t len; };
				static const ClrSite clrSites[] = {
					{ "41 80 A1 5C 09 00 00 FE 41 80 A1 76",                            "r9",  "r9d", 0x71, 8 }, // SetMode fn 0x140191ff0 branch
					{ "80 A1 5C 09 00 00 FE 80 89 5F 09 00 00 40 80 A1 BA 06 00 00 EF C7", "rcx", "ecx", 0x73, 7 }, // 0x14019d2ba (+[0x934]=0)
					{ "80 A3 5C 09 00 00 FE 80 8B 5F 09 00",                            "rbx", "ebx", 0x74, 7 }, // 0x14019fb94 (+[0x934]=0)
					{ "80 A7 5C 09 00 00 FE 48 8B CF E8 E9",                            "rdi", "edi", 0x75, 7 }, // 0x1401a1c58
					{ "80 A6 5C 09 00 00 FE 45 22 CD 44 89",                            "rsi", "esi", 0x76, 7 }, // 0x1401a4631 (apply params)
				};
				for (const auto& cs : clrSites)
				{
					constants[0] = cs.tag;
					match = FindOne(cs.sig);
					const std::string R = cs.reg;
					const std::string asmStr =
						"push rax; push r10; push r11; pushfq; "
						"movzx r11d, word ptr [" + R + " + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
						"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
						"lea r11, [rip + ?0]; add r11, r10; "
						"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], " + std::string(cs.low) + "; "
						"movzx eax, byte ptr [" + R + " + 0x95c]; mov dword ptr [r11 + 4], eax; "
						"mov eax, dword ptr [" + R + " + 0x934]; mov dword ptr [r11 + 8], eax; "
						"mov eax, dword ptr [" + R + " + 0xc64]; mov dword ptr [r11 + 12], eax; "
						"movzx eax, word ptr [" + R + " + 0x7f0]; mov dword ptr [r11 + 16], eax; "
						"A: popfq; pop r11; pop r10; pop rax; "
						"and byte ptr [" + R + " + 0x95c], 0xfe";
					ParametricASMJump(asmStr.c_str(), match, 0, cs.len);
				}
				// Site 0x72 = the kill path inside TakeDamage 0x140198560 (the one the Qator
				// trace hit). Its frame is 8 pushes + sub rsp,0x58, so with our 4 pushes the
				// return address sits at [rsp+0xb8] and the r8d home slot (damage amount,
				// stored by the prologue at entry+0x18) at [rsp+0xd0]; r15d holds the damage
				// flags. v0 = [0x934] before the write, v1 = flags, v2 = amount, v3 = caller low32.
				constants[0] = 0x72;
				match = FindOne("80 A3 5C 09 00 00 FE 0F B6 83 5D 09");
				ParametricASMJump(
					"push rax; push r10; push r11; pushfq; "
					"movzx r11d, word ptr [rbx + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
					"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
					"lea r11, [rip + ?0]; add r11, r10; "
					"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], ebx; "
					"mov eax, dword ptr [rbx + 0x934]; mov dword ptr [r11 + 4], eax; "
					"mov dword ptr [r11 + 8], r15d; "
					"mov eax, dword ptr [rsp + 0xd0]; mov dword ptr [r11 + 12], eax; "
					"mov eax, dword ptr [rsp + 0xb8]; mov dword ptr [r11 + 16], eax; "
					"A: popfq; pop r11; pop r10; pop rax; "
					"and byte ptr [rbx + 0x95c], 0xfe", match, 0, 0x7);
			}

			// --- ApplyHit entry 0x1401969b0 (who is hitting the boss, and how often) ---
			// rcx = victim actor, edx = hit flags, r8d = attacker channel, [rsp] = return
			// address of the attack code path (after our 4 pushes: [rsp+0x20]). The Qator
			// trace showed party members (ch 1/2) draining 604 HP at 1-2 per RENDERED frame.
			// v0 = flags, v1 = attacker ch, v2 = caller low32, v3 = HP before. Re-executes
			// the displaced 5-byte prologue store 'mov [rsp+0x18], r8d'.
			constants[0] = 0x80; // APPLY_HIT
			match = FindOne("44 89 44 24 18 89 54 24 10 53 56 57 41 54 48 81 EC 88 00 00 00");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; "
				"movzx r11d, word ptr [rcx + 0x360]; cmp r11d, 0x2019; je B; cmp r11d, 0x200B; jne A; B: "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
				"lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 20], ecx; "
				"mov dword ptr [r11 + 4], edx; mov dword ptr [r11 + 8], r8d; "
				"mov rax, qword ptr [rsp + 0x20]; mov dword ptr [r11 + 12], eax; "
				"mov eax, dword ptr [rcx + 0x934]; mov dword ptr [r11 + 16], eax; "
				"A: popfq; pop r11; pop r10; pop rax; "
				"mov dword ptr [rsp + 0x18], r8d", match, 0, 0x5);

			// --- battle-script opcode stream (dispatcher 0x140370c70) ---
			// At 0x140370d64 the thread record (rbx) holds opcode [rbx+0x24], the owner
			// channel as float (xmm0, about to be stored at [rbx+0x34]) and the script PC
			// [rbx+0x28]; the thread index (edx at entry, homed at entry+0x10) sits at
			// [rsp+0x128] after our 4 pushes (frame = 6 pushes + 0xc8). Enemy channels
			// (>=6) only. v0 = opcode, v1 = channel, v2 = PC, v3 = thread index. Used to
			// diff General Qator Bashtar's AI script flow between 30 and 120 fps.
			constants[0] = 0x90; // SCRIPT_OP
			match = FindOne("F3 0F 11 43 34 0F B7 47 02 A8 03 74 0E");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; "
				"cvttss2si r11d, xmm0; cmp r11d, 6; jl A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; "
				"lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov eax, dword ptr [rbx + 0x24]; mov dword ptr [r11 + 4], eax; "
				"cvttss2si eax, xmm0; mov dword ptr [r11 + 8], eax; "
				"mov eax, dword ptr [rbx + 0x28]; mov dword ptr [r11 + 12], eax; "
				"mov eax, dword ptr [rsp + 0x128]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ebx; "
				"A: popfq; pop r11; pop r10; pop rax; "
				"movss dword ptr [rbx + 0x34], xmm0; movzx eax, word ptr [rdi + 2]", match, 0, 0x9);

			// --- script query results: op 0x122 (actor property getter 0x1401a2080, index
			// float[rec+0x38]) and op 0x153 (AI-block per-target table word, sub 1/2/3)
			// - the values the boss AI loop branches on. Hooked at each handler's result
			// store; enemy channels only. v0 = index/sub, v1 = value, v2 = channel, v3 = PC.
			constants[0] = 0x91; // PROP_GET
			match = FindOne("C2 0F 5B C0 F3 0F 11 43 30 48 83 C4 20 5B C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 40");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; cvttss2si r11d, dword ptr [rbx + 0x34]; cmp r11d, 6; jl A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; cvttss2si eax, dword ptr [rbx + 0x38]; mov dword ptr [r11 + 4], eax; mov dword ptr [r11 + 8], edx; "
				"cvttss2si eax, dword ptr [rbx + 0x34]; mov dword ptr [r11 + 12], eax; mov eax, dword ptr [rbx + 0x28]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ebx; "
				"A: popfq; pop r11; pop r10; pop rax; movss dword ptr [rbx + 0x30], xmm0; add rsp, 0x20", match, 4, 13);
			{
				struct TSite { const char* sig; uint32_t sub; };
				static const TSite tsites[] = {
					{ "F3 41 0F 11 43 30 48 83 C4 28 C3 49 8B CA E8 A9", 3 },
					{ "F3 41 0F 11 43 30 48 83 C4 28 C3 49 8B CA E8 80", 2 },
					{ "F3 41 0F 11 43 30 48 83 C4 28 C3 49 8B CA E8 57", 1 },
				};
				for (const auto& ts : tsites)
				{
					constants[0] = ts.sub;
					match = FindOne(ts.sig);
					ParametricASMJump(
						"push rax; push r10; push rcx; pushfq; cvttss2si ecx, dword ptr [r11 + 0x34]; cmp ecx, 6; jl A; "
						"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea rcx, [rip + ?0]; add rcx, r10; "
						"mov dword ptr [rcx], 0x92; mov dword ptr [rcx + 4], $0; mov dword ptr [rcx + 8], edx; "
						"cvttss2si eax, dword ptr [r11 + 0x34]; mov dword ptr [rcx + 12], eax; mov eax, dword ptr [r11 + 0x28]; mov dword ptr [rcx + 16], eax; mov dword ptr [rcx + 20], r11d; "
						"A: popfq; pop rcx; pop r10; pop rax; movss dword ptr [r11 + 0x30], xmm0; add rsp, 0x28", match, 0, 10);
				}
			}

			// --- script op 0x15F "event bit set?" TRUE result (0x1403541bc). The boss idle
			// loop polls 4 such bits and only leaves when one is set. v0 = word sel
			// (0:+0x1ac 1:+0x1a0 2:+0x1a8), v1 = bit, v2 = channel, v3 = PC. Enemy only.
			constants[0] = 0x93; // EVBIT_TRUE
			match = FindOne("45 0F A3 D1 73 08 C7 41 30 00 00 80 3F C3");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; cvttss2si r11d, dword ptr [rcx + 0x34]; cmp r11d, 6; jl A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; cvttss2si eax, dword ptr [rcx + 0x38]; mov dword ptr [r11 + 4], eax; cvttss2si eax, dword ptr [rcx + 0x3c]; mov dword ptr [r11 + 8], eax; "
				"cvttss2si eax, dword ptr [rcx + 0x34]; mov dword ptr [r11 + 12], eax; mov eax, dword ptr [rcx + 0x28]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ecx; "
				"A: popfq; pop r11; pop r10; pop rax; mov dword ptr [rcx + 0x30], 0x3f800000", match, 6, 13);

			// FALSE result of the same op (0x1403541c4), restricted to the boss idle loop's
			// four polls (PC 0x3EF0..0x3FD0) so the log names the (word, bit) pairs it waits on.
			// (signature must not overlap the TRUE-site patch above, which already replaced
			// the preceding bytes with a jmp - anchor on the site + padding + next fn start)
			constants[0] = 0x94; // EVBIT_FALSE
			match = FindOne("C7 41 30 00 00 00 00 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC F3 0F 2C 41 34 45 33 C9");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; cvttss2si r11d, dword ptr [rcx + 0x34]; cmp r11d, 6; jl A; "
				"mov eax, dword ptr [rcx + 0x28]; cmp eax, 0x3EF0; jl A; cmp eax, 0x3FD0; jg A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; cvttss2si eax, dword ptr [rcx + 0x38]; mov dword ptr [r11 + 4], eax; cvttss2si eax, dword ptr [rcx + 0x3c]; mov dword ptr [r11 + 8], eax; "
				"cvttss2si eax, dword ptr [rcx + 0x34]; mov dword ptr [r11 + 12], eax; mov eax, dword ptr [rcx + 0x28]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ecx; "
				"A: popfq; pop r11; pop r10; pop rax; mov dword ptr [rcx + 0x30], 0", match, 0, 7);

			// --- RaiseAiEvent 0x140265750 (ecx=channel, edx=kind 1..5, r8d=bit): the ONLY
			// writer that sets bits in the AI-block event words (kind 4 -> +0x1a0, 5 -> +0x1a8),
			// proven by a DR0 write watch. v0 = kind, v1 = bit, v2 = channel, v3 = caller low32
			// ([rsp+0x20] after our 4 pushes). Re-executes the displaced rip-relative
			// 'cmp byte ptr [0x140658663], 0' via ?2. Enemy channels only.
			constants[0] = 0x95; // AI_RAISE
			match = FindOne("80 3D ? ? ? ? 00 4C 63 C9 0F 84");
			pointers[2] = baseaddress + 0x658663;
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; cmp ecx, 6; jl A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 4], edx; mov dword ptr [r11 + 8], r8d; mov dword ptr [r11 + 12], ecx; "
				"mov rax, qword ptr [rsp + 0x20]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ecx; "
				"A: popfq; pop r11; pop r10; pop rax; cmp byte ptr [rip + ?2], 0", match, 0, 7);

			// --- animation event-track player 0x1403bd780 (rcx = player: frame 24.8 at
			// +0x6c, rate +0x74, last processed frame +0x70, anim data +8; owner actor at
			// [[rcx]+0x478]). RaiseAiEvent is called from here (kind/bit = keyframe events),
			// so the boss's "attack now" bit is an animation keyframe. Log the boss's player
			// whenever its integer frame changes. v0 = frame(24.8), v1 = rate bits,
			// v2 = last frame, v3 = anim data low32.
			{
				auto lastFrame = trampoline->Pointer<uint32_t>(); *lastFrame = 0xFFFFFFFF;
				constants[0] = 0x96; // ANIM_FRAME
				match = FindOne("40 57 48 83 EC 40 48 8B 01 48 8B F9 48 83 B8 80 04 00 00 00");
				pointers[2] = reinterpret_cast<uintptr_t>(lastFrame);
				ParametricASMJump(
					"push rax; push r10; push r11; pushfq; "
					"mov rax, qword ptr [rcx]; mov rax, qword ptr [rax + 0x478]; test rax, rax; je A; movzx r11d, word ptr [rax + 0x360]; cmp r11d, 0x200B; jne A; "
					"mov eax, dword ptr [rcx + 0x6c]; shr eax, 8; cvttss2si r10d, dword ptr [rcx + 0x7c]; dec r10d; cmp eax, r10d; je L; cmp eax, dword ptr [rip + ?2]; je A; L: mov dword ptr [rip + ?2], eax; "
					"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
					"mov dword ptr [r11], $0; mov eax, dword ptr [rcx + 0x6c]; mov dword ptr [r11 + 4], eax; mov eax, dword ptr [rcx + 0x74]; mov dword ptr [r11 + 8], eax; "
					"mov eax, dword ptr [rcx + 0x70]; mov dword ptr [r11 + 12], eax; mov rax, qword ptr [rcx + 8]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ecx; "
					"A: popfq; pop r11; pop r10; pop rax; push rdi; sub rsp, 0x40; mov rax, qword ptr [rcx]", match, 0, 9);
			}

			// --- AI-block begin-frame clear 0x14027caf0 (rcx = AI block, channel byte at +8):
			// zeroes the event words unless the keep flag +0x1b4 is set. Log only when it is
			// about to wipe a NON-ZERO +0x1a0 of an enemy block: v0 = +0x1a0, v1 = +0x1a8,
			// v2 = keep flag, v3 = channel. Re-executes 'mov eax,[rcx+0x1ac]'.
			constants[0] = 0x97; // AI_CLEAR
			match = FindOne("8B 81 AC 01 00 00 33 D2 89 81 B0 01 00 00");
			ParametricASMJump(
				"push rax; push r10; push r11; pushfq; movsx r11d, byte ptr [rcx + 8]; cmp r11d, 6; jl A; "
				"mov eax, dword ptr [rcx + 0x1a0]; test eax, eax; je A; "
				"mov r10d, dword ptr [rip + ?1]; inc dword ptr [rip + ?1]; and r10d, 0x1ff; imul r10d, r10d, 24; lea r11, [rip + ?0]; add r11, r10; "
				"mov dword ptr [r11], $0; mov dword ptr [r11 + 4], eax; mov eax, dword ptr [rcx + 0x1a8]; mov dword ptr [r11 + 8], eax; "
				"movzx eax, byte ptr [rcx + 0x1b4]; mov dword ptr [r11 + 12], eax; movsx eax, byte ptr [rcx + 8]; mov dword ptr [r11 + 16], eax; mov dword ptr [r11 + 20], ecx; "
				"A: popfq; pop r11; pop r10; pop rax; mov eax, dword ptr [rcx + 0x1ac]", match, 0, 6);

			LogF("[Watchdog] enabled: 26 event hooks (3 state entries, 4 s1/s3 kills, run attempts, AI behaviour issue, 6 flag95c clears, apply-hit, script opcodes, prop/ai-table queries, event-bit true/false, ai-raise, anim-frame, ai-clear)");
		}

		// Analog movement ([Movement] AnalogTiers=1): the left stick's tilt
		// smoothly scales the movement-speed multiplier between the game's
		// normal speed and a cap; L3 toggles the cap between the stock 1.5x and
		// 2.0x tiers with the game's own speed icons. The watcher drives the
		// game's native applier (see StartAutoTierWatcher); here the L3 handler
		// is rewired from a 3-tier cycle into the 1<->2 cap toggle, keeping the
		// icons and every built-in gate working exactly like the stock feature.
		if (GetPrivateProfileIntW(L"Movement", L"AnalogTiers", 0, wcModulePath) != 0)
		{
			g_analogTiers = 1;
			g_tiltWalk = GetPrivateProfileIntW(L"Movement", L"WalkTiltPercent", 80, wcModulePath);
			g_tiltSprint = GetPrivateProfileIntW(L"Movement", L"SprintTiltPercent", 95, wcModulePath);
			g_minSpeedPct = GetPrivateProfileIntW(L"Movement", L"MinSpeedPercent", 60, wcModulePath);
			g_dashAtCap = GetPrivateProfileIntW(L"Movement", L"DashAtCap", 1, wcModulePath) != 0;
			if (g_minSpeedPct < 20) g_minSpeedPct = 20;
			if (g_minSpeedPct > 100) g_minSpeedPct = 100;
			match = FindOne("8B 0D F3 4D 3E 00 B8 56 55 55 55");
			pointers[0] = baseaddress + 0x658BD8;
			ParametricASMJump("mov qword ptr [rsp + 0x50], rbp; mov qword ptr [rsp + 0x58], rsi; mov qword ptr [rsp + 0x60], rdi; mov qword ptr [rsp + 0x68], r14; mov ecx, dword ptr [rip + ?0]; cmp ecx, 2; je A; mov ecx, 2; jmp B; A: mov ecx, 1; B: mov dword ptr [rip + ?0], ecx; movsxd rax, ecx", match, 0, 0x38);
			LogF("[Movement] analog speed on (min %d%%, ramp %d%%..%d%%), L3 toggles the 1.5x/2x cap",
				g_minSpeedPct, g_tiltWalk, g_tiltSprint);

			// [Movement] AnalogGlobalsFix (default 1 with AnalogTiers): SetActorParam
			// 0x14019c620 (script ops 15/16) sets an actor's walk/run/sprint speed
			// (params 7/8/9 -> slots +0x29c/+0x2a0/+0x2a4) and, for any party-type actor
			// ([actor+0xcfc] type 2), ALSO publishes that speed and the mode to the
			// SHARED globals [0x636FF4+..]/[0x636FF0] the tier applier 0x19C960 reads.
			// A party member's script setting its own (lower) run speed therefore made
			// the next applier call compute the PLAYER's speed from the member's base:
			// the "speed randomly drops and sticks until a jump/L3 re-sets it" bug,
			// only on maps with party members around. Publish the globals for the
			// player's own channel [0x658CF4] only; the x m1 boost for party members
			// is kept exactly as stock. Four sites: base (param 4, [0x637000] x m2) and
			// the three mode sites; each block is re-executed with the extra channel test.
			if (GetPrivateProfileIntW(L"Movement", L"AnalogGlobalsFix", 1, wcModulePath) != 0)
			{
				struct GSite { const char* sig; uint32_t constCell, mulCell, mode, len; bool hasPc; };
				static const GSite gsites[] = {
					// actor fn 0x14019c620: base (param 4) + modes 7/8/9 (no script PC available)
					{ "3D 00 00 08 00 75 10 F3 0F 11 35 F0 A8 49 00 F3 0F 59 35 F0 A8 49 00", 0x637000, 0x637008, 0, 0x17, false },
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 96 A8 49 00 F3 0F 59 35 9E A8 49 00 C7 05 80 A8 49 00 07 00 00 00", 0x636FF4, 0x637004, 7, 0x21, false },
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 3C A8 49 00 F3 0F 59 35 40 A8 49 00 C7 05 22 A8 49 00 08 00 00 00", 0x636FF8, 0x637004, 8, 0x21, false },
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 D8 A7 49 00 F3 0F 59 35 D8 A7 49 00 C7 05 BA A7 49 00 09 00 00 00", 0x636FFC, 0x637004, 9, 0x21, false },
					// script op 15/16 handler 0x14035cf2d: its own inline copies (rcx = op record, PC at +0x28)
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 8E A0 2D 00 F3 0F 59 35 96 A0 2D 00 C7 05 78 A0 2D 00 07 00 00 00", 0x636FF4, 0x637004, 7, 0x21, true },
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 33 A0 2D 00 F3 0F 59 35 33 A0 2D 00 C7 05 15 A0 2D 00 09 00 00 00", 0x636FFC, 0x637004, 9, 0x21, true },
					{ "3D 00 00 08 00 75 1A F3 0F 11 35 D6 9F 2D 00 F3 0F 59 35 DA 9F 2D 00 C7 05 BC 9F 2D 00 08 00 00 00", 0x636FF8, 0x637004, 8, 0x21, true },
				};
				auto spring = reinterpret_cast<uint32_t*>(trampoline->RawSpace(8 + 16 * 24));
				memset(spring, 0, 8 + 16 * 24);
				g_spLog = spring;
				auto ctl = trampoline->Pointer<int>(); *ctl = *reinterpret_cast<volatile int*>(baseaddress + 0x658CF4);
				g_ctlChanCell = ctl;
				for (const auto& gs : gsites)
				{
					match = FindOne(gs.sig);
					pointers[0] = reinterpret_cast<uintptr_t>(ctl);   // controlled character's channel (mirrored by the watcher)
					pointers[1] = baseaddress + gs.constCell;
					pointers[2] = baseaddress + gs.mulCell;
					pointers[3] = baseaddress + 0x636FF0;      // mode
					pointers[4] = reinterpret_cast<uintptr_t>(spring);
					constants[0] = gs.mode;
					// ring-log every party-type write (param, value, channel, PC), then publish
					// the globals only when the writer is the player's channel
					const std::string logPart = std::string(
						"push r11; push rax; lea r11, [rip + ?4]; mov eax, dword ptr [r11]; inc dword ptr [r11]; and eax, 15; imul eax, eax, 24; add r11, rax; add r11, 8; "
						"mov dword ptr [r11], $0; movss dword ptr [r11 + 4], xmm6; movsx eax, byte ptr [rbx + 0x18]; mov dword ptr [r11 + 8], eax; ")
						+ (gs.hasPc ? "mov eax, dword ptr [rcx + 0x28]; mov dword ptr [r11 + 12], eax; " : "mov dword ptr [r11 + 12], 0; ")
						+ "pop rax; pop r11; ";
					if (gs.mode)
						ParametricASMJump(("cmp eax, 0x80000; jne E; " + logPart +
							"movsx eax, byte ptr [rbx + 0x18]; cmp eax, dword ptr [rip + ?0]; jne M; "
							"movss dword ptr [rip + ?1], xmm6; mov dword ptr [rip + ?3], $0; M: mulss xmm6, dword ptr [rip + ?2]; E: nop").c_str(), match, 0, gs.len);
					else
						ParametricASMJump(("cmp eax, 0x80000; jne E; " + logPart +
							"movsx eax, byte ptr [rbx + 0x18]; cmp eax, dword ptr [rip + ?0]; jne M; "
							"movss dword ptr [rip + ?1], xmm6; M: mulss xmm6, dword ptr [rip + ?2]; E: nop").c_str(), match, 0, gs.len);
				}
				LogF("[Movement] AnalogGlobalsFix on: move-mode/speed globals published for the player only");
			}
		}

		const int ResX = GetPrivateProfileIntW(L"OverrideRes", L"ResX", 0, wcModulePath);
		const int ResY = GetPrivateProfileIntW(L"OverrideRes", L"ResY", 0, wcModulePath);

		if (ResX > 0 && ResY > 0)
		{
			LogF("[Resolution] applying %dx%d", ResX, ResY);
			auto windowres = FindOne("C4 40 5F C3 C7 07 80 07 00 00 C7 03 38 04 00 00");
			Patch<int32_t>(windowres.get<void>(0x6), ResX);
			Patch<int32_t>(windowres.get<void>(0xC), ResY);

			auto renderres = FindOne("75 21 41 0B C4 B9 80 07 00 00 BA 38 04 00 00");
			Patch<int32_t>(renderres.get<void>(0x6), ResX);
			Patch<int32_t>(renderres.get<void>(0xB), ResY);

			float aspect_ratio = static_cast<float>(ResX) / static_cast<float>(ResY);

			auto native_res_output_fix = FindOne("82 13 FF FF FF 48 8B 46 14 48 8B 5E 0C 4C 8D 86");
			Patch<int8_t>(native_res_output_fix.get<void>(0x8), 0x0c);

			if (aspect_ratio != SIXTEENBYNINE)
			{
				bool isultrawide = aspect_ratio > SIXTEENBYNINE;

				auto geometry_aspect_ratio = FindOne("00 C7 87 74 08 00 00 39 8E E3 3F C7 87 50 06 00"); //This is not a FOV slider, it just rescales the geometry so that it isn't stretched in the viewport, like the HUD
				Patch<float>(geometry_aspect_ratio.get<void>(0x7), aspect_ratio);

				//Stretched video files fix (not the ideal approach, would be better to find where it gets copied from to begin with, but since this only runs on movie playback, it's an acceptable compromise)
				if (isultrawide)
				{
					constants[0] = 0x710;
					constants[1] = 0x70C;
					constants[2] = 0x704;
					param_floats[0] = SIXTEENBYNINE;
				}
				else
				{
					constants[0] = 0x70C;
					constants[1] = 0x710;
					constants[2] = 0x708;
					param_floats[0] = 1.0f / SIXTEENBYNINE;
				}
				param_floats[1] = 0.5f;
				pointers[0] = baseaddress + 0x53730;
				match = FindOne("00 00 E8 91 7D E5 FF 80 3D 16 C4 46 00 00 75 20");
				ParametricASMJump("call ?0; mov rax, qword ptr gs:0x58; mov rax, [rax]; mov rax, [rax + 0x8]; movss xmm0, dword ptr [rax + $0]; mulss xmm0, %0; movss xmm1, dword ptr [rax + $1]; movss dword ptr [rax + $1], xmm0; subss xmm1, xmm0; mulss xmm1, %1; movss dword ptr [rax + $2], xmm1", match, 0x2, 0x7);

				if (GetPrivateProfileIntW(L"OverrideRes", L"KeepUIAspectRatio", 0, wcModulePath))
				{

					float correction;
					if (isultrawide)
					{
						correction = -(SIXTEENBYNINE) / aspect_ratio;
						constants[0] = *reinterpret_cast<uint32_t*>(&correction);
						param_floats[0] = -correction;

						//Background UI
						match = FindOne("00 0F 28 C7 C7 85 DC 00 00 00 00 00 80 BF F3 0F");
						ParametricASMJump("mov dword ptr [rbp + 0xdc], $0; divss xmm0, xmm6; xorps xmm6, xmm6; mulss xmm0, %0; mov dword ptr [rbp + 0xe0], 0x0; mov dword ptr [rbp + 0xe8], 0x1; mov dword ptr [rbp + 0xec], 0x3f800000; movss dword ptr [rbp + 0xd0], xmm0", match, 0x4, 0x3B);
						//Foreground UI
						match = FindOne("00 00 00 C7 85 DC 00 00 00 00 00 80 BF 44 89 B5");
						ParametricASMJump("mov dword ptr [rbp + 0xdc], $0; mov dword ptr [rbp + 0xe0], r14d; mov dword ptr [rbp + 0xe8], 0x1; cvtsi2ss xmm0, rcx; mov dword ptr [rbp + 0xec], 0x3f800000; divss xmm7, xmm0; xorps xmm0, xmm0; cvtsi2ss xmm0, rax; mulss xmm7, %0; movss dword ptr [rbp + 0xd0], xmm7", match, 0x3, 0x3E);

						//Fix for the lock-on reticle being off
						param_floats[0] = 960.0f;
						param_floats[1] = aspect_ratio / (SIXTEENBYNINE);
						match = FindOne("41 89 0E 8B 8B 1C 0D 00 00 48 8B 5C 24 50 89 0E");
						ParametricASMJump("cvtsi2ss xmm0, ecx; subss xmm0, %0; mulss xmm0, %1; addss xmm0, %0; cvtss2si ecx, xmm0; mov dword ptr [r14], ecx; mov ecx, dword ptr [rbx + 0xd1c];", match, 0, 0x9);

					}
					else
					{
						correction = aspect_ratio / (SIXTEENBYNINE);
						constants[0] = *reinterpret_cast<uint32_t*>(&correction);
						param_floats[0] = correction;

						//Background UI
						match = FindOne("00 C7 85 EC 00 00 00 00 00 80 3F F3 0F 11 85 D0");
						ParametricASMJump("mov dword ptr [rbp + 0xec], $0; movss dword ptr [rbp + 0xd0], xmm0; movaps xmm0, xmm8; mulss xmm0, %0", match, 0x1, 0x17);
						//Foreground UI
						match = FindOne("C7 85 EC 00 00 00 00 00 80 3F F3 0F 5E F8 0F 57");
						ParametricASMJump("mov dword ptr [rbp + 0xec], $0; divss xmm7, xmm0; xorps xmm0, xmm0; cvtsi2ss xmm0, rax; movss dword ptr [rbp + 0xd0], xmm7; mulss xmm8, %0", match, 0, 0x1E);

						//Fix for the lock-on reticle being off
						param_floats[0] = 540.0f;
						param_floats[1] = (SIXTEENBYNINE) / aspect_ratio;
						match = FindOne("00 48 8B 5C 24 50 89 0E 48 8B 74 24 58 48 83 C4");
						ParametricASMJump("mov rbx, qword ptr [rsp + 0x50]; cvtsi2ss xmm0, ecx; subss xmm0, %0; mulss xmm0, %1; addss xmm0, %0; cvtss2si ecx, xmm0;", match, 0x1, 0x6);

					}
				}
			}

			if ((ResX % 1920 != 0) || (ResY % 1080 != 0))
			{
				//Fix to UI getting scaled via nearest neighbor (point sampling) for non 1080p multiples by changing the D3D11_FILTER parameter of D3D11_SAMPLER_DESC before the game calls CreateSamplerState 
				match = FindOne("48 8D 54 24 38 48 8B 01 FF 90 B8 00 00 00 85 C0");
				ParametricASMJump("lea rdx, [rsp + 0x38]; cmp dword ptr [rdx], 0; jnz A; mov dword ptr [rdx], 0x15; A: nop;", match, 0, 0x5);

				//Font fix
				match = FindOne("02 F3 0F 10 5C 24 48 89 42 10 41 8B 42 04 0F 57");
				param_floats[0] = max(max(static_cast<float>(ResX) / 1920.0f, static_cast<float>(ResY) / 1080.0f) - 1.0f, 0);
				ParametricASMJump("movss xmm4, [r10]; addss xmm4, %0; movss [rdx + 0x10], xmm4; movss xmm4, [r10 + 0x4]; addss xmm4, %0; movss [rdx + 0x14], xmm4; movss xmm4, [r10 + 0x8]; subss xmm4, %0; movss [rdx + 0x28], xmm4; movss xmm4, [r10 + 0xC]; subss xmm4, %0; movss [rdx + 0x2C], xmm4; xorps xmm4, xmm4; movaps xmm0, xmm4;", match, 0X7, 0x25);

				//Fix for a problematic texture with wrong coordinates
				match = FindOne("0F 41 0F BF 04 0A 66 0F 6E C0 0F 5B C0 F3 0F 11");
				ParametricASMJump("mov rax, 0x01C201E4018C01D0; cmp rax, qword ptr [r10 + rcx + 8]; jz A; mov rax, 0x01C201E401C101D0; cmp rax, qword ptr [r10 + rcx + 8]; jnz B; A: mov byte ptr [r10 + rcx + 0xC], 0xE2; B: movsx eax, word ptr [r10 + rcx]; ", match, 0X1, 0x6);
			}

		}

		const int framerateint = GetPrivateProfileIntW(L"OverrideFramerate", L"FpsCap", 0, wcModulePath);

		if (framerateint > 30)
		{
			LogF("[Framerate] applying cap %d", framerateint);

			// Bisect switches for the issue #12 softlock: each disables one
			// group of dedup patches so the culprit can be narrowed down
			// in-game without rebuilding. Side effects while disabled are the
			// original >30fps glitches (double triggers / fast counters).
			const bool disableCounterDedup = GetPrivateProfileIntW(L"Diagnostics", L"DisableCounterDedup", 0, wcModulePath) != 0;
			const bool disableTriggerDedup = GetPrivateProfileIntW(L"Diagnostics", L"DisableTriggerDedup", 0, wcModulePath) != 0;
			if (disableCounterDedup)
				LogF("[Framerate] counter dedup patches DISABLED via ini (bisect mode)");
			if (disableTriggerDedup)
				LogF("[Framerate] trigger dedup patches DISABLED via ini (bisect mode)");
			float framerate = framerateint;
			g_framerate = framerate;
			if (framerate > 120.0f)
			{
				MessageBox(
					NULL,
					(LPCWSTR)L"Due to technical limitations, the framerate of the game cannot exceed 120fps.\nTo make this message disappear on startup, lower the value in FFT0HD Unlocker.ini.\nThe game will now start with a 120fps cap.",
					(LPCWSTR)L"Framerate Warning",
					MB_ICONWARNING | MB_OK
				);
				framerate = 120.0f;
			}

			/*[ref] points to the absolute address in the PSP elf on which similar patches were applied*/

			//Actual value used for the frame limiter (also likely to [ref: 0x0008614C] since there are no other 0.0333333 floats referenced in the code)
			auto frameratelimit = FindOne("88 88 08 3D 89 88 08 3D 35 FA 0E 3D 29 5C 0F 3D");
			Patch<float>(frameratelimit.get<void>(0x4), 1.0f / framerate);
			DWORD dwProtect;
			VirtualProtect(frameratelimit.get<void>(0x4), sizeof(float), PAGE_EXECUTE_READWRITE, &dwProtect); //This variable needs to be writable by the movie function below
			// [Diagnostics] FpsToggleKey=1: F10 flips the live frame limiter between the
			// configured cap and 30 fps mid-game (same cell the movie relock writes), so a
			// frozen boss can be observed at 30 fps without replaying the approach. The
			// per-fps fixes stay as compiled for the cap, so this is a diagnostic, not a
			// clean 30 fps reference.
			if (GetPrivateProfileIntW(L"Diagnostics", L"FpsToggleKey", 0, wcModulePath) != 0)
			{
				g_fpsCapCell = reinterpret_cast<volatile float*>(frameratelimit.get_uintptr(0x4));
				g_fpsCapValue = 1.0f / framerate;
				StartFpsToggleWatcher();
			}

			//Framerate here is used as an integer
			//[ref: 0x0004F084]
			auto frint1 = FindOne("88 42 30 B0 01 C3 04 1E 88 42 30 32 C0 C3 CC");
			Patch<uint8_t>(frint1.get<void>(0x7), framerate);
			//[ref: 0x00179AEC]
			auto frint2 = FindOne("05 7F 4A 3E 00 83 F8 1E 7C 23 C7 05 70 4A 3E");
			Patch<uint8_t>(frint2.get<void>(0x7), framerate);
			//[ref: 0x00208D84] Maybe fixes some timers?
			auto frint3 = FindOne("51 01 00 00 81 BB 70 6E 00 00 84 03 00 00 0F 8E");
			Patch<uint32_t>(frint3.get<void>(0xA), framerate * 30);
			//Party stats pop up time (when not in battle or near a relic terminal)
			auto frint4 = FindOne("FF FF 32 C0 EB 70 C7 05 AF BC 37 00 96 00 00 00");
			Patch<uint32_t>(frint4.get<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = FindOne("0F 84 7D 00 00 00 C7 05 7A BC 37 00 96 00 00 00");
			Patch<uint32_t>(frint4.get<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = FindOne("ED BB 37 00 EB 91 C7 05 E1 BB 37 00 96 00 00 00");
			Patch<uint32_t>(frint4.get<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = FindOne("08 01 00 00 75 84 C7 05 0C BD 37 00 96 00 00 00");
			Patch<uint32_t>(frint4.get<void>(0xC), (framerate / 30.0f) * 150.0f);
			//"Reraise" and other status effects on top of the characters name
			auto frint5 = FindOne("C0 75 43 41 FF 40 08 41 83 78 08 14 0F 8C B1 00");
			Patch<uint8_t>(frint5.get<void>(0xB), (framerate / 30.0f) * 20.0f);
			frint5 = FindOne("D1 73 43 41 FF 40 08 41 83 78 08 14 7C 66 83 F8");
			Patch<uint8_t>(frint5.get<void>(0xB), (framerate / 30.0f) * 20.0f);
			//Flashing examine button
			auto frint6 = FindOne("DB 78 4E 8B 4D CB FF C9 75 47 2B FA 83 FB 14 7C");
			Patch<uint8_t>(frint6.get<void>(0xE), (framerate / 30.0f) * 20.0f);
			frint6 = FindOne("00 69 C9 00 00 00 0D 2B C1 EB 24 83 FB 0A 7D 11");
			Patch<uint8_t>(frint6.get<void>(0x6), 255.0f / ((framerate / 30.0f) * 19.0f)); //0x0D000000 is a uint32_t but the only relevant part are the highest 8 bits (0D) since it's used to calculate the alpha channel.
			Patch<uint8_t>(frint6.get<void>(0xD), (framerate / 30.0f) * 10.0f);
			frint6 = FindOne("8B CB B8 00 00 00 FF 69 C9 00 00 00 0D 2B C1 EB");
			Patch<uint8_t>(frint6.get<void>(0xC), 255.0f / ((framerate / 30.0f) * 19.0f));
			frint6 = FindOne("0E 8B C3 69 C0 00 00 00 0D 81 C7 00 00 00 FB 03");
			Patch<uint8_t>(frint6.get<void>(0x8), 255.0f / ((framerate / 30.0f) * 19.0f));
			//Random encounters timer
			auto frint7 = FindOne("00 00 C7 83 68 6E 00 00 2C 01 00 00 E8 CF 8E EF");
			Patch<uint32_t>(frint7.get<void>(0x8), framerate * 10);
			//SP support timers
			auto frint8 = FindOne("00 00 00 4C 89 53 08 6B C0 1E 89 43 04 48 8B 5C");
			Patch<uint8_t>(frint8.get<void>(0x9), framerate);
			//Minimap popup delay in the upper right corner when an area text is being shown (on the field)
			auto frint9 = FindOne("8B 05 8A A9 1F 00 B9 AA 00 00 00 3B EE 0F 4C C1");
			Patch<uint32_t>(frint9.get<void>(0x7), (framerate / 30.0f) * 170.0f);
			//RTS turret
			auto frint10 = FindOne("00 00 B8 3C 00 00 00 66 89 87 D4 01 00 00 B8 02");
			Patch<uint32_t>(frint10.get<void>(0x3), ((framerate * 2.0f - 30.0f) / 30.0f) * 60.0f); //Also take into consideration the time for moving down
			frint10 = FindOne("1D B8 06 00 00 00 66 89 B7 C8 01 00 00 66 89 87");
			Patch<uint32_t>(frint10.get<void>(0x2), (framerate / 30.0f) * 6.0f);
			frint10 = FindOne("E2 7E 06 41 83 EE 02 EB 06 41 BE E2 FF FF FF 45");
			Patch<int8_t>(frint10.get<void>(), (framerate / 30.0f) * -30.0f);
			Patch<int32_t>(frint10.get<void>(0xB), (framerate / 30.0f) * -30.0f);
			frint10 = FindOne("41 83 FD 02 0F 87 AA 03 00 00 41 83 FE E2 0F 85");
			Patch<int8_t>(frint10.get<void>(0xD), (framerate / 30.0f) * -30.0f);
			//RTS Fort reshooting time
			auto frint11 = FindOne("FF FF E8 D9 6C FF FF B8 64 00 00 00 66 89 86 C2");
			Patch<uint32_t>(frint11.get<void>(0x8), (framerate / 30.0f) * 100.0f);
			//RTS MP regen interval near Fort
			auto frint12 = FindOne("D0 E8 22 6A D4 FF B8 19 00 00 00 66 89 83 BE 01");
			Patch<uint32_t>(frint12.get<void>(0x7), (framerate / 30.0f) * 25.0f);

			//[ref: 0x000A9AF4]
			auto charactersanimationspeed = FindOne("80 A3 B6 09 00 00 F7 C7 83 D8 05 00 00 00 00 80 3F");
			//The lip sync function that the game uses for real time cutscenes REALLY
			//doesn't like exactly representable values here: the original workaround
			//nudged 0.5f (60fps) to 29.9f/60, but 120fps produces exactly 0.25f and
			//broke lips the same way. Nudge whenever the division is exact (60, 120,
			//also 40/48/80/96...), keep the true ratio for inexact ones (90 etc).
			float charanimspeed = 30.0f / framerate;
			if (charanimspeed * framerate == 30.0f)
				charanimspeed = 29.9f / framerate;
			Patch<float>(charactersanimationspeed.get<void>(0xD), charanimspeed);

			//Always use in conjunction with $ or damage will be registered multiple times
			auto rtsanimationspeed = FindOne("85 D2 74 0A C7 82 0C 06 00 00 00 00 80 3F 48 83");
			Patch<float>(rtsanimationspeed.get<void>(0xA), 30.0f / framerate);

			//Relock the game back to 30fps when prerendered cutscenes are playing (and unlock it again if needed when the skip cutscene menu shows up so it isn't slowed down (it still is when fading out, can't change that or audio would get out of sync))
			auto movielimit = FindOne("02 32 C9 48 8B 05 7E F9 60 00 88 88 D0 00 00 00");
			float inv_framerate = 1.0f / framerate;
			constants[0] = *reinterpret_cast<uint32_t*>(&inv_framerate); //(0x3D088889 is 1.0/30.0)
			pointers[0] = baseaddress + 0x75B7CC; //(1 when the skip cutscene menu is showing, 0 otherwise)
			pointers[1] = frameratelimit.get_uintptr(0x4);
			ParametricASMJump("mov [rax + 0xD0], cl; cmp cl, 0; je A; cmp dword ptr [rip + ?0], 1; je A; mov dword ptr [rip + ?1], 0x3D088889; jmp B; A: mov dword ptr [rip + ?1], $0; B: nop", movielimit, 0xA, 0x10);

			//Characters walking speeds (with check for cutscenes) [ref: 0x00083CF8]
			// The scaled function (0x1403C0C12) writes the per-frame delta to the mover:
			// on the RUN branch (mover flag bit 0x2 set) it stores X=xmm1 (@0xC0C47),
			// Y=xmm0 (@0xC0C42) and Z=xmm6 (@0xC0C59). The stock patch scales xmm1 (X)
			// and xmm6 (Z) by 30/fps but NOT xmm0 (Y): xmm0 is computed at 0x1403C0C33,
			// BEFORE our inject at 0x1403C0C3C, and flows straight to the Y store. So at
			// 120fps the vertical delta of a run is 4x the horizontal - harmless on flat
			// ground (Y=0 unless bit 0x2), but it wrecks a scripted stair climb like the
			// ch2 sub-boss. [Movement] BossVerticalFix=1 also scales xmm0, completing the
			// fix. On this branch xmm0 feeds only the Y store (X uses xmm1), so scaling it
			// cannot double-scale X; bit-exact no-op at 30fps.
			const bool bossVerticalFix = GetPrivateProfileIntW(L"Movement", L"BossVerticalFix", 0, wcModulePath) != 0;
			match = FindOne("24 0F 28 CE F3 0F 59 4C 24 20 F3 0F 11 43 1C F3");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x658F70;
			pointers[1] = baseaddress + 0x6D1CEC;
			{
				std::string walkAsm = "mulss xmm1, dword ptr [rsp + 0x20]; cmp dword ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 0; jnz B; A: mulss xmm1, %0; mulss xmm6, %0; ";
				if (bossVerticalFix)
					walkAsm += "mulss xmm0, %0; ";
				walkAsm += "B: nop";
				ParametricASMJump(walkAsm.c_str(), match, 0x4, 0xA);
			}
			if (bossVerticalFix)
				LogF("[Movement] BossVerticalFix on: run vertical delta scaled to 30/%.0f", framerate);

			//---- Experimental high-fps boss-movement fixes -------------------
			//All four are EXPERIMENTAL and default to OFF, so the stock high-fps
			//behaviour is the baseline. Trace evidence (30fps vs 120fps) shows the
			//boss's scripted run state (mover flag bit 0x2 -> "mode 6", the only
			//state in which [mover+0x78] is ever non-zero) is never entered at
			//120fps at all, which none of these address; they are kept switchable
			//so a clean baseline can be captured without a rebuild.
			//  [Movement] BossFixPace / BossFixNav / BossFixTurn / BossFixProfile
			const bool bossFixPace    = GetPrivateProfileIntW(L"Movement", L"BossFixPace", 0, wcModulePath) != 0;
			const bool bossFixNav     = GetPrivateProfileIntW(L"Movement", L"BossFixNav", 0, wcModulePath) != 0;
			const bool bossFixTurn    = GetPrivateProfileIntW(L"Movement", L"BossFixTurn", 0, wcModulePath) != 0;
			const bool bossFixProfile = GetPrivateProfileIntW(L"Movement", L"BossFixProfile", 0, wcModulePath) != 0;
			LogF("[Movement] boss experimental fixes: pace=%d nav=%d turn=%d profile=%d",
				bossFixPace, bossFixNav, bossFixTurn, bossFixProfile);

			//Boss/leader AI action pacing (high-fps freeze fix). The enemy-brain
			//update (0x45C020) advances a boss's action-step counter [actor+0x934]
			//once per [brain+0x1C4] countdown; that countdown decrements every
			//RENDERED frame and reloads from a 30Hz-designed global [0x76D7D8], so
			//above 30fps a scripted boss/leader runs out its action sequence
			//~framerate/30x too fast and freezes (regular enemies skip this block
			//via the class-bit fork at 0x45C2EA, so they are unaffected). Scale the
			//reload by framerate/30 to restore the intended 30Hz cadence.
			//NOTE: tested, did NOT fix the 120fps boss bug. Off by default.
			if (bossFixPace)
			{
				int bossPace = static_cast<int>(framerate / 30.0f + 0.5f);
				if (bossPace < 1) bossPace = 1;
				match = FindOne("66 FF 8E C4 01 00 00 66 44 39 B6 C4 01 00 00 7F 6D 0F B7 05 80 15 31 00 66 89 86 C4 01 00 00");
				constants[0] = static_cast<uintptr_t>(bossPace);
				//eax already holds the reload value (from the preceding movzx at +0x11);
				//scale it and store. Injecting on the store avoids re-reading the global.
				ParametricASMJump("imul eax, eax, $0; mov word ptr [rsi + 0x1c4], ax", match, 0x18, 0x1f);
				LogF("[Movement] boss AI pacing fix applied (action-step reload x%d for 30Hz)", bossPace);
			}

			//Boss navmesh path-following (high-fps beeline fix). The boss scripted
			//"move to position" action steps a lead GUIDE point toward each route
			//waypoint over a fixed FRAME COUNT (word[action+0x1bc], decremented
			//1/frame, no dt) while the body chases the guide at a wall-clock-correct
			//(30/fps-scaled) speed. Above 30fps the guide sprints ~fps/30x ahead of
			//the body, so the steering vector aims at the FINAL destination and the
			//boss beelines into geometry instead of hugging the route (only bosses
			//run this scripted navmesh move; regulars chase the player live). Gate
			//the two guide steppers to 30Hz so the guide advances in lockstep with
			//the body. Ref: nav hunt wf_0a1dd08b; steppers 0x455A50 (curved) /
			//0x455900 (linear), guide-apply 0x472900, integrator 0x3C0C80.
			//NOTE: tested, did NOT fix the 120fps boss bug. Off by default. It also
			//uses ONE shared beat counter for every actor that calls a stepper, so
			//with two bosses on screen the gate fires erratically per actor.
			if (bossFixNav)
			{
				int navStep = static_cast<int>(framerate / 30.0f + 0.5f);
				if (navStep < 1) navStep = 1;
				if (navStep > 1)
				{
					auto navPhase = trampoline->Pointer<uint32_t>();
					*navPhase = 0;
					constants[0] = static_cast<uintptr_t>(navStep);
					//curved stepper 0x140455A50 (rcx=action): on a non-30Hz-beat
					//frame return immediately (advance nothing); else run prologue.
					match = FindOne("48 8B C4 48 89 58 10 55 48 8D 68 A1");
					pointers[0] = reinterpret_cast<uintptr_t>(navPhase);
					ParametricASMJump("push rcx; mov eax, dword ptr [rip + ?0]; inc eax; mov dword ptr [rip + ?0], eax; xor edx, edx; mov ecx, $0; div ecx; pop rcx; test edx, edx; je A; ret; A: mov rax, rsp; mov qword ptr [rax + 0x10], rbx", match, 0, 0x7);
					//linear stepper 0x140455900 (rcx=action)
					match = FindOne("40 53 48 81 EC A0 00 00 00 0F 29 B4");
					pointers[0] = reinterpret_cast<uintptr_t>(navPhase);
					ParametricASMJump("push rcx; mov eax, dword ptr [rip + ?0]; inc eax; mov dword ptr [rip + ?0], eax; xor edx, edx; mov ecx, $0; div ecx; pop rcx; test edx, edx; je A; ret; A: push rbx; sub rsp, 0xa0", match, 0, 0x8);
					LogF("[Movement] boss navmesh path-follow fix applied (guide gated to 30Hz, step=%d)", navStep);
				}
			}

			//Enemy navmesh STEERING turn (high-fps beeline fix, part 2). The AI
			//move-to-position steering (0x449A50) turns the actor's heading toward
			//the target by a FIXED +/-0.03 rad step per frame (and snaps within
			//0.03 rad), with NO time term -> 0.9 rad/s at 30fps but 3.6 rad/s at
			//120fps, so at high fps the actor instantly faces the FINAL target and
			//beelines instead of lagging into the curve. Scale the step AND the
			//snap threshold by 30/fps so angular velocity matches 30fps at any
			//framerate (restores 30fps behavior for every actor that uses it).
			//Ref: nav hunt wf_0a1dd08b candidate 0x44a0af.
			//NOTE: tested, did NOT fix the 120fps boss bug. Off by default.
			if (bossFixTurn && framerate > 30.0f)
			{
				match = FindOne("F3 0F 10 0D F5 5A 13 00 F3 0F 10 15 35 64 13 00 0F 2F C8 72 0B");
				param_floats[0] = 0.03f * 30.0f / framerate;   //+step (and +threshold)
				param_floats[1] = -0.03f * 30.0f / framerate;  //-step (and -threshold)
				ParametricASMJump("movss xmm1, %0; movss xmm2, %1", match, 0, 0x10);
				LogF("[Movement] enemy nav turn step scaled to 30Hz (%.4f rad/frame)", param_floats[0]);
			}

			//Controlled character turning speed (a bit broken above 90 fps) [ref: 0x00006734 to 0x00006744]
			match = FindOne("F3 0F 59 49 40 F3 0F 59 CA F3 0F 59 51 34 F3 0F 59 0D 1F C4 3A 00");
			param_floats[0] = 15.0f / framerate;
			ParametricASMJump("movss xmm1, dword ptr [rcx + 0x40]; movss xmm2, dword ptr [rcx + 0x34]; mulss xmm1, %0", match, 0, 0x16);

			//First cutscene slow-motion walk speed [ref: 0x00006998]
			//This is the mode1 branch of the scripted motion-profile clock 0x1D3F00,
			//which advances phase [rcx+4] by a hardcoded +1.0 per rendered frame.
			//IMPORTANT: the same mode-1 profiles are what the battle event-script
			//"move actor" opcodes (0xE4/0xE5) build for a scripted boss entrance, so
			//this fix stretches those moves to their authored wall-clock length while
			//the script VM's own per-command wait may still be counted in frames.
			//That asymmetry is a live suspect for the 120fps sub-boss stair bug, hence
			//the switch: [Movement] CutsceneWalkFix=0 disables it for A/B testing.
			//Default 1 = the original mod's shipped behaviour.
			if (GetPrivateProfileIntW(L"Movement", L"CutsceneWalkFix", 1, wcModulePath) != 0)
			{
				match = FindOne("20 5B C3 F3 0F 10 41 04 F3 0F 58 05 69 BE 3A 00");
				// [Movement] TurnPhaseFullRate=1: the actual ch2 sub-boss carrier.
				// Step E proved the boss's TRANSLATION profile (actor+0x160) is dead
				// (mode 0) while its TURN profile (actor+0x1a8) is the only live mode-1
				// profile - and this clock fix scales EVERY mode-1 profile, so it
				// quartered the boss's turn phase at 120fps (traced rPhase steps 0.25 vs
				// 1.0 at 30fps). The facing servo then never converges, the boss can't
				// face its corridor and runs down the stairs; CutsceneWalkFix=0 "fixes"
				// it only by returning EVERY turn to full rate (global cutscene speedup).
				// The turn profile reaches the clock from exactly one site, 0x1401b960f
				// (verified: no other caller leas actor+0x1a8). So run that one call at
				// full rate and leave the other 8 - the cutscene TRANSLATION walk at
				// 0x1401b9792 included - at 30/fps. A shared cell defaults to 30/fps
				// (identical to the stock fix for all callers) and is briefly forced to
				// 1.0 around the turn call, then restored; the region 0x1401b95f2..b9614
				// is linear so the wrap is safe. Net: the boss's turn behaves as with
				// CutsceneWalkFix=0, with none of its global side effect.
				if (framerate > 30.0f && GetPrivateProfileIntW(L"Movement", L"TurnPhaseFullRate", 1, wcModulePath) != 0)
				{
					// Refined split (traced): running the WHOLE +0x1a8 turn at full rate
					// regressed the player - a scripted "turn, then hand control over" step
					// (state-4 waiter 0x14019c01a waits on [actor+0x1a8]==0 then zeroes
					// [0x160]) self-terminates 4x early at h=1, so the tier-speed apply that
					// follows lands before the analog watcher re-blends -> low initial speed.
					// The right axis is NOT actor but PROFILE TYPE, told apart by entry phase:
					// the facing SERVO (boss state 3, player stick-turn) is rebuilt every frame
					// and reaches the clock with phase [rcx+4]==0; a scripted turn arrives with
					// phase>0 from its 2nd frame. Rule in the arm: step 1.0 when phase==0
					// (servo, full rate - kills decay/spin), else g_step=30/fps (scripted turn
					// completes at the right wall-clock time). Gated to the +0x1a8 call only by
					// g_phaseRule, set around 0x1401b960f, so the other 8 clock callers are
					// untouched. At 30fps g_step==1.0 so both arms match: bit-exact no-op.
					auto gStep = trampoline->Pointer<float>();     *gStep = 30.0f / framerate;
					auto gPhaseRule = trampoline->Pointer<uint32_t>(); *gPhaseRule = 0;
					auto gZero = trampoline->Pointer<float>();     *gZero = 0.0f;
					auto gOne = trampoline->Pointer<float>();      *gOne = 1.0f;
					pointers[0] = reinterpret_cast<uintptr_t>(gStep);
					pointers[1] = reinterpret_cast<uintptr_t>(gPhaseRule);
					pointers[2] = reinterpret_cast<uintptr_t>(gZero);
					pointers[3] = reinterpret_cast<uintptr_t>(gOne);
					// Rule value 2 = ALWAYS full rate (see EnemyTurnFullRate below).
					ParametricASMJump("cmp dword ptr [rip + ?1], 0; je G; cmp dword ptr [rip + ?1], 2; je F; ucomiss xmm0, dword ptr [rip + ?2]; jne G; F: addss xmm0, dword ptr [rip + ?3]; jmp D; G: addss xmm0, dword ptr [rip + ?0]; D: nop", match, 0x8, 0x10);
					// enable the phase rule only across the lone +0x1a8 clock call (E8 @0x1401b960f)
					match = FindOne("F3 0F 10 1D 00 66 3C 00 0F 28 D0");
					pointers[0] = reinterpret_cast<uintptr_t>(gPhaseRule);
					pointers[1] = baseaddress + 0x1D3F00;          // clock 0x1401d3f00
					// call via register: the framework's "call ?N" only resolves as the FIRST
					// asm instruction; mid-block, load the target and call the register (r11 is
					// volatile and the clock clobbers it anyway).
					//
					// [Movement] EnemyTurnFullRate=1 (General Qator Bashtar freeze): the enemy
					// AI scheduler is entirely RENDER-frame driven (action countdown word
					// [actor+0xc6a] -1 per frame, turn re-issues on the same cadence). Qator's
					// AI issues a scripted "turn to face" (dispatcher state 4, waits for
					// [actor+0x1a8]==0) and re-issues it on a frame cadence; at 120fps the turn
					// phase steps 0.25 so the profile is rebuilt before it can ever finish
					// (traced: rPhase jumping 1.0->5.0->4.0->1.75, ccc stuck at 4 from ~7 s into
					// the arena), and the boss hangs. Enemy actors (class word[actor+0x360]
					// 0x20xx) therefore get rule 2 = full rate for the whole turn profile, so
					// their turns finish on the same frame cadence as their AI, as at 30fps.
					// Player/party (0x00xx) keep the servo-only rule (their spawn-turn timing
					// regressed at full rate). Bit-exact no-op at 30fps (g_step==1.0 anyway).
					if (GetPrivateProfileIntW(L"Movement", L"EnemyTurnFullRate", 1, wcModulePath) != 0)
					{
						ParametricASMJump("mov dword ptr [rip + ?0], 1; movzx r11d, word ptr [rbx + 0x360]; and r11d, 0xFF00; cmp r11d, 0x2000; jne H; mov dword ptr [rip + ?0], 2; H: lea r11, [rip + ?1]; call r11; mov dword ptr [rip + ?0], 0", match, 0xB, 0x10);
						LogF("[Movement] TurnPhaseFullRate on: turn servo at full rate, scripted turns + translation kept at 30/%.0f; EnemyTurnFullRate on (enemy class 0x20xx turns always full rate)", framerate);
					}
					else
					{
						ParametricASMJump("mov dword ptr [rip + ?0], 1; lea r11, [rip + ?1]; call r11; mov dword ptr [rip + ?0], 0", match, 0xB, 0x10);
						LogF("[Movement] TurnPhaseFullRate on: turn servo at full rate, scripted turns + translation kept at 30/%.0f", framerate);
					}
				}
				else
				{
					param_floats[0] = 30.0f / framerate;
					ParametricASMJump("addss xmm0, %0", match, 0x8, 0x10);
					LogF("[Movement] cutscene/scripted-move profile clock scaled to 30/%.0f", framerate);
				}
			}
			else
				LogF("[Movement] cutscene/scripted-move profile clock fix DISABLED (A/B test)");

			//Scripted motion-profile VELOCITY-UNIT fix -- the missing companion to
			//the phase fix above, and the actual cause of the 120fps boss beeline.
			//
			//The profile's +0x30 field is the engine's velocity carrier. The curve
			//evaluator 0x1D3890 writes it as the per-CALL displacement (s(t)-s_prev,
			//at 0x1D38D2/0x1D390A/0x1D3957), EXCEPT on the terminal frame (0x1D3960)
			//where it stores [rcx+0x3C], already a velocity. But every consumer reads
			//it back as a per-30Hz-frame VELOCITY and uses it as the v0 seed when it
			//REBUILDS the profile - e.g. the facing servo, rebuilt every single frame:
			//  0x19BD7E lea rcx,[rbx+0x1A8] / 0x19BD9F movss xmm3,[rbx+0x1D8] (=+0x30)
			//  / 0x19BDD4 call 0x1D3BF0, which zeroes the accumulator (0x1D3C67) and
			//  the phase and re-seeds +0x30/+0x34 from that argument.
			//So the recurrence is v(n+1) = v(n)*h + 0.5*a*h^2 for phase step h.
			//At h=1.0 (30fps) it ramps linearly to the authored cap. Once the phase fix
			//makes h=30/fps, it becomes a GEOMETRIC DECAY to a fixed point ~0.167*a per
			//30Hz-frame at 120fps - roughly a 20x loss of turn authority. The actor can
			//no longer turn, so it drives straight at its goal and ploughs into geometry
			//it would normally walk around (the ch2 stair sub-boss jams on the railing).
			//With the phase fix off, turn rate and translation are compressed by the
			//same 4x, so the path SHAPE survives and only the wall-clock speed is wrong
			//- exactly what the A/B test showed.
			//Fix: rescale +0x30 back to per-30Hz-frame velocity units after each step,
			//skipping the terminal frame (where it is already a velocity). Then
			//v(n+1) = v(n) + 0.5*a*h, i.e. +0.5*a per 30Hz-frame at any framerate.
			//Identity at 30fps (factor 1.0). Ref: hunt wf_0641a583.
			//DEFAULT OFF: this over-reached. +0x30 is read BOTH as a v0 seed on
			//profile rebuild (the facing servo) AND directly as this-frame's motion
			//by most consumers, so scaling it globally x(fps/30) quadruples ALL actor
			//movement and turning at 120fps and wrecks player control. Left switchable
			//for further investigation only. Ref: broke everything, user test.
			if (GetPrivateProfileIntW(L"Movement", L"ProfileVelocityFix", 0, wcModulePath) != 0)
			{
				//sig starts at 0x1D3F53 (movss [rcx+4],xmm0 / call 0x1D3890 / the two
				//instructions we replace / jb). Inject 10 -> 0x1D3F5D, jumpback 19 ->
				//0x1D3F66, a 9-byte region nothing branches into. rcx survives the
				//call (0x1D3890 only uses it as a base); xmm0 holds the return value
				//and is untouched; xmm5 is dead across the region; the trailing comiss
				//re-establishes the flags the original jb consumes.
				match = FindOne("F3 0F 11 41 04 E8 ? ? ? ? F3 0F 10 69 04 0F 2F 69 08 72");
				param_floats[0] = framerate / 30.0f;
				ParametricASMJump(
					"movss xmm5, dword ptr [rcx + 4]; comiss xmm5, dword ptr [rcx + 8]; jae A; "
					"movss xmm5, dword ptr [rcx + 0x30]; mulss xmm5, %0; "
					"movss dword ptr [rcx + 0x30], xmm5; "
					"A: movss xmm5, dword ptr [rcx + 4]; comiss xmm5, dword ptr [rcx + 8]",
					match, 10, 19);
				LogF("[Movement] scripted-profile velocity-unit fix applied (+0x30 x%.2f)", param_floats[0]);
			}

			//Scripted motion-profile clock, mode2 (edx==2) branch [0x1D3F1F] --
			//the SIBLING of the cutscene-walk fix above, in the same function
			//0x1D3F00, left unpatched by the original mod. This trapezoidal profile
			//(accel/cruise/decel) is what drives a boss/leader's scripted "run to
			//battle position" speed: the caller (0x1B9580) evaluates it and hands the
			//FINITE DIFFERENCE of its output to SetSpeed 0x3C09A0 -> [mover+0x78].
			//Because phase counts RENDERED frames (+1.0/frame, no dt) but the profile
			//durations are authored for 30Hz, above 30fps the profile saturates
			//~fps/30x too soon; once saturated its per-frame delta -> 0, so the boss'
			//move speed collapses to 0, the speed-mover 0x3C0BC0 takes its zero
			//branch and the boss freezes / falls back to the guide-delta and beelines
			//into geometry (30fps trace: clean trapezoid plateaus at 19.000 & 72.000;
			//120fps trace: a few accel blips then speed==0 for 993/996 samples).
			//Scale the phase step by 30/fps exactly like the mode1 fix -> the profile
			//spans the full wall-clock route at any framerate and the finite-diff
			//speed stays healthy. Identity (x1.0) at 30fps. Ref: hunt wf_26440db7.
			//NOTE: tested, did NOT fix the 120fps boss bug -- the trace shows the boss
			//never enters the run state at all at 120fps, so rescaling the run's own
			//profile cannot help. Kept switchable; off by default.
			if (bossFixProfile)
			{
				match = FindOne("F3 0F 10 41 04 F3 0F 58 05 95 BE 3A 00");
				param_floats[0] = 30.0f / framerate;
				ParametricASMJump("addss xmm0, %0", match, 0x5, 0xD);
				LogF("[Movement] boss scripted-move profile fix applied (mode2 phase step 30/%.0f)", framerate);
			}

			//[Movement] AnimLastFrameFix=1 (General Qator Bashtar freeze, and any AI that
			//waits on an animation's last-frame event). The animation player steps the
			//24.8 frame counter by (int)(rate*256) per RENDERED frame (0x1403bdb81) and,
			//for a non-looping clip, finishes when the new frame is PAST (length-1)
			//(0x1403bdc33: comiss newFrame, (len-1)*256; jbe notDone), clamping to the
			//last frame. At 30fps (rate 1.0) the last frame is always reached exactly,
			//dispatched once as a normal frame, and only the NEXT step finishes - so the
			//keyframe events on the last frame (kind 4 bit 0 = "clip finished, act") are
			//raised on two consecutive frames. At 120fps (rate 0.249) the step jumps from
			//33.95 straight past 34.0, finishing in the same step: the last-frame event is
			//raised once, the AI-block begin-frame clear wipes it before the boss's script
			//polls, and the script idles forever (traced: Qator's clip 9BB50EA0 stops at
			//34.00, kind4/bit0 fires once, poll at pc 3F80 sees it clear; at 30fps the same
			//poll sees it SET and the script proceeds to its attack path).
			//Fix: when the OLD frame was still below the last frame and the NEW one is past
			//it, clamp to the last frame and stay playing; the next step finishes as at
			//30fps. With integer steps this case cannot occur, so it is a bit-exact no-op
			//at 30fps. rcx=player, eax=new frame, xmm1=(len-1)*256, xmm2=256.0; r9-r11/xmm3
			//are free here (the function tail-calls with rcx/xmm1 only).
			if (framerate > 30.0f && GetPrivateProfileIntW(L"Movement", L"AnimLastFrameFix", 0, wcModulePath) != 0)
			{
				match = FindOne("0F 2F C1 76 50 F3 0F 2C C1 41 83 E0 FE");
				auto notDone = trampoline->Pointer<uintptr_t>();
				*notDone = match.get_uintptr(0x55);          // 0x1403bdc88 = the 'not finished' continuation
				pointers[0] = reinterpret_cast<uintptr_t>(notDone);
				ParametricASMJump(
					"comiss xmm0, xmm1; jbe N; "
					"movss xmm3, dword ptr [rcx + 0x74]; mulss xmm3, xmm2; cvttss2si r9d, xmm3; mov r10d, eax; sub r10d, r9d; "
					"cvttss2si r11d, xmm1; cmp r10d, r11d; jge F; mov dword ptr [rcx + 0x6c], r11d; "
					"N: jmp qword ptr [rip + ?0]; F: nop", match, 0, 5);
				LogF("[Movement] AnimLastFrameFix on: non-looping clips dwell one frame on their last frame before finishing (as at 30fps)");
			}

			//[Movement] AiEventKeepFix=1 - the actual General Qator Bashtar carrier.
			//Enemy AI scripts (battle-script VM, runner 0x140370c70) tick at 30Hz, but
			//the AI-block event words they poll (+0x1a0/+0x1a8, raised by animation
			//keyframes through RaiseAiEvent) are zeroed by the begin-frame clear
			//0x14027caf0 on EVERY rendered frame. Traced in-frame order at 120fps:
			//raise -> [poll only on a tick frame] -> clear. A one-frame event raised on
			//a frame without a script tick is wiped before any script sees it; Qator's
			//"clip finished, act" event (kind 4 bit 0) is exactly that, so his idle loop
			//never leaves and he hangs. At 30fps every frame is a tick frame, so nothing
			//is ever lost. Fix: count VM runner entries; in the clear, zero the event
			//words only if the counter moved since this block's last zeroing (i.e. a
			//script tick happened), otherwise keep them for the next tick. At 30fps the
			//counter moves every frame: identical to stock.
			if (framerate > 30.0f && GetPrivateProfileIntW(L"Movement", L"AiEventKeepFix", 1, wcModulePath) != 0)
			{
				auto vmTicks = trampoline->Pointer<uint32_t>(); *vmTicks = 0;
				auto lastSeen = reinterpret_cast<uint32_t*>(trampoline->RawSpace(0x42 * 4));
				memset(lastSeen, 0, 0x42 * 4);
				// VM thread runner entry: count ticks (re-executes the two homing stores)
				match = FindOne("89 54 24 10 48 89 4C 24 08 53 55 56 57 41 54 41 55 48 81 EC C8 00 00 00");
				pointers[0] = reinterpret_cast<uintptr_t>(vmTicks);
				ParametricASMJump("inc dword ptr [rip + ?0]; mov dword ptr [rsp + 0x10], edx; mov qword ptr [rsp + 8], rcx", match, 0, 9);
				// begin-frame clear: keep events unless a tick happened since the last zeroing
				match = FindOne("38 91 B4 01 00 00 75 0D 48 89 91 A8 01 00 00 89 91 A0 01 00 00");
				pointers[0] = reinterpret_cast<uintptr_t>(vmTicks);
				pointers[1] = reinterpret_cast<uintptr_t>(lastSeen);
				ParametricASMJump(
					"cmp byte ptr [rcx + 0x1b4], dl; jne K; push r10; push r11; mov eax, dword ptr [rip + ?0]; movsx r10, byte ptr [rcx + 8]; test r10, r10; js Z; cmp r10, 0x41; ja Z; "
					"lea r11, [rip + ?1]; cmp eax, dword ptr [r11 + r10*4]; je S; mov dword ptr [r11 + r10*4], eax; "
					"Z: pop r11; pop r10; mov qword ptr [rcx + 0x1a8], rdx; mov dword ptr [rcx + 0x1a0], edx; jmp K; S: pop r11; pop r10; K: nop", match, 0, 0x15);
				LogF("[Movement] AiEventKeepFix on: AI event bits survive until the next 30Hz script tick");
			}

			//[Movement] AiCountdownFix=1: the enemy action scheduler's pause between
			//decisions, word[actor+0xc6a], is decremented once per RENDERED frame
			//(0x140194bed: add word [rbx+0xc6a], -1) and reloaded from a 30Hz-authored
			//value, so above 30fps every non-script enemy re-decides framerate/30 times
			//too often (traced: soldiers class 0x2016 sit in the "waiting" state 70% of
			//samples at 30fps vs 9% at 120fps). Bosses driven by battle scripts are
			//unaffected either way (the VM ticks at 30Hz). Fix: count AI frames at the
			//AI begin-frame loop (0x140263b9c, once per rendered frame) and only apply
			//the decrement on every k-th frame, k = round(framerate/30). Not installed
			//at 30fps (k would be 1).
			{
				const int k = static_cast<int>(framerate / 30.0f + 0.5f);
				if (k > 1 && GetPrivateProfileIntW(L"Movement", L"AiCountdownFix", 1, wcModulePath) != 0)
				{
					auto aiFrame = trampoline->Pointer<uint32_t>(); *aiFrame = 0;
					match = FindOne("48 8B 0D 9D 4C 3F 00 41 B9 42 00 00 00");
					pointers[0] = reinterpret_cast<uintptr_t>(aiFrame);
					pointers[1] = match.get_uintptr(0x7) + *reinterpret_cast<int32_t*>(match.get<void>(0x3)); // the AI table cell the displaced mov reads
					ParametricASMJump("inc dword ptr [rip + ?0]; mov rcx, qword ptr [rip + ?1]; mov r9d, 0x42", match, 0, 0xD);
					match = FindOne("B8 FF FF 00 00 66 01 83 6A 0C 00 00");
					pointers[0] = reinterpret_cast<uintptr_t>(aiFrame);
					constants[0] = k;
					ParametricASMJump(
						"push rax; push rdx; push rcx; pushfq; mov eax, dword ptr [rip + ?0]; xor edx, edx; mov ecx, $0; div ecx; test edx, edx; jne S; "
						"popfq; pop rcx; pop rdx; pop rax; mov eax, 0xffff; add word ptr [rbx + 0xc6a], ax; jmp E; S: popfq; pop rcx; pop rdx; pop rax; E: nop", match, 0, 0xC);
					LogF("[Movement] AiCountdownFix on: AI decision countdown steps every %d rendered frames (30Hz cadence)", k);
				}
			}

			//Camera distance in the first cutscene [ref: 0x00155CB0]
			match = FindOne("00 44 0F 29 44 24 70 F3 44 0F 10 05 DC BF 29 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm8, %0", match, 0x7, 0x10);

			//Fix camera movement in the panning cutscenes (i.e new area introductions in Akademia)
			match = FindOne("0F 85 E9 01 00 00 8B 05 94 51 37 00 FF C0 2B C8");
			param_floats[0] = framerate / 30.0f;
			pointers[0] = baseaddress + 0x658FA8;
			ParametricASMJump("mov eax, dword ptr [rip + ?0]; cvtsi2ss xmm11, ecx; mulss xmm11, %0; cvtss2si ecx, xmm11;", match, 0x6, 0xC);

			//Fix camera rotation in the panning cutscenes (i.e new area introductions in Akademia)
			match = FindOne("00 8B 05 7D 4D 37 00 FF C0 2B C8 89 05 73 4D 37");
			param_floats[0] = framerate / 30.0f;
			pointers[0] = baseaddress + 0x658FAC;
			ParametricASMJump("mov eax, dword ptr [rip + ?0]; cvtsi2ss xmm11, ecx; mulss xmm11, %0; cvtss2si ecx, xmm11;", match, 0x1, 0x7);

			//Part of the HUD [ref: 0x002491E4]
			match = FindOne("0F 5B C0 F3 0F 5E C8 F3 0F 58 CA 41 0F 2F CF");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("divss xmm1, xmm0; mulss xmm1, %0; addss xmm1, xmm2", match, 0x3, 0xB);

			//[ref: 0x001F9924 and 0x001F9934]
			match = FindOne("05 57 A6 24 00 F3 41 0F 59 C8 D1 E8 41 84 C7 74");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm1, xmm8; mulss xmm1, %0", match, 0x5, 0xA);

			//Stick response curve override ([Camera] TurnCurveExponent, 1..4).
			//Stock game: pad axes use deflection^2, mouse axes are linear. The
			//curve is applied where |stick| turns into rotation speed, at the
			//same spots the framerate fixes below already patch (horizontal)
			//plus two new injections for the vertical axis.
			int curveExp = GetPrivateProfileIntW(L"Camera", L"TurnCurveExponent", 0, wcModulePath);
			if (curveExp > 4)
				curveExp = 4;
			//Radial mode applies the curve to the stick vector LENGTH instead of
			//each axis separately, so diagonals aren't penalized twice (the pad
			//stick is circular: a diagonal gives each axis only ~0.7 deflection).
			const bool radialCurve = GetPrivateProfileIntW(L"Camera", L"RadialCurve", 0, wcModulePath) != 0;
			if (radialCurve && curveExp > 3)
				curveExp = 3;
			//Knee curve (pad only, implies radial): piecewise response — up to
			//CurveKneeDeflection% of stick travel the speed rises linearly to
			//CurveKneeSpeed% of maximum, the remaining travel ramps to 100%.
			//E.g. 80/50: first 80% of deflection = 0..50% speed, last 20% = 50..100%.
			int kneePos = GetPrivateProfileIntW(L"Camera", L"CurveKneeDeflection", 0, wcModulePath);
			int kneeSpd = GetPrivateProfileIntW(L"Camera", L"CurveKneeSpeed", 50, wcModulePath);
			const bool kneeCurve = kneePos >= 5 && kneePos <= 95;
			float kneeB = 0, kneeC = 0, kneeK = 0;
			//Real pads don't reach the full ±255 off the cardinal axes (measured
			//~218 at diagonals) — treat CurveSaturation% of the range as "full"
			//so slight tilts off an axis don't fall below the knee.
			int satPct = GetPrivateProfileIntW(L"Camera", L"CurveSaturation", 85, wcModulePath);
			if (satPct < 50) satPct = 50;
			if (satPct > 100) satPct = 100;
			//Shape of the segment below the knee: 1 = linear, 3 = very eased
			//start; fractional values (e.g. 2.4) blend the two nearest powers
			wchar_t expBuf[32];
			GetPrivateProfileStringW(L"Camera", L"CurveInnerExponent", L"2", expBuf, 32, wcModulePath);
			float innerExpF = static_cast<float>(_wtof(expBuf));
			if (innerExpF < 1.0f) innerExpF = 1.0f;
			if (innerExpF > 3.0f) innerExpF = 3.0f;
			if (kneeCurve)
			{
				if (kneeSpd < 1) kneeSpd = 1;
				if (kneeSpd > 99) kneeSpd = 99;
				kneeK = kneePos / 100.0f;
				const float s = kneeSpd / 100.0f;
				kneeB = (1.0f - s) / (1.0f - kneeK);    // slope above the knee
				kneeC = s - kneeK * kneeB;              // f(mag) = B + C/mag above the knee
				if (kneeC > -1e-4f && kneeC < 1e-4f)
					kneeC = -1e-4f;
				g_tuneInnerX10 = static_cast<int>(innerExpF * 10.0f + 0.5f);
				float kc1, kc2, kc3;
				KneeInnerCoeffs(kneeK, s, g_tuneInnerX10, &kc1, &kc2, &kc3);
				//dedicated (non-deduplicated) slots so the tuner window can
				//rewrite the curve live without touching shared constants
				auto pk = trampoline->Pointer<float>(); *pk = kneeK; g_kneeKPtr = pk;
				auto pc = trampoline->Pointer<float>(); *pc = kneeC; g_kneeCPtr = pc;
				auto pb = trampoline->Pointer<float>(); *pb = kneeB; g_kneeBPtr = pb;
				auto p1 = trampoline->Pointer<float>(); *p1 = kc1; g_kneeC1Ptr = p1;
				auto p2 = trampoline->Pointer<float>(); *p2 = kc2; g_kneeC2Ptr = p2;
				auto p3 = trampoline->Pointer<float>(); *p3 = kc3; g_kneeC3Ptr = p3;
				auto ps = trampoline->Pointer<float>(); *ps = 100.0f / satPct; g_satMulPtr = ps;
				g_tuneKneePos = kneePos;
				g_tuneKneeSpd = kneeSpd;
				g_tuneSat = satPct;
				LogF("[Camera] knee curve: %d%% deflection -> %d%% speed (inner exp %.1f)", kneePos, kneeSpd, innerExpF);
			}
			else if (curveExp > 0)
				LogF("[Camera] stick response curve exponent = %d%s", curveExp, radialCurve ? " (radial)" : "");

			//Fix controller camera speed (orbital) for controller
			//At the injection point xmm7 already holds deflection^2 (stock pad
			//curve); sqrtss recovers |x| to build other exponents from it.
			match = FindOne("C7 F3 0F 59 C7 0F 28 F8 F3 0F 59 3D AC 2D 32 00");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x61141C;
			{
				std::string curveasm;
				if (kneeCurve)
				{
					//Circle-to-square remap + knee curve. Effective per-axis
					//deflection e = |x| * mag / max(|x|,|y|) (a full diagonal
					//counts as full deflection on BOTH axes), then the knee
					//shape: speed = e * f(e); f = B + C/e above the knee,
					//below it f = c1 + c2*e + c3*e^2 (live inner exponent).
					param_floats[1] = 255.0f;
					param_floats[2] = 1.0f;
					param_floats[7] = 1e-6f;
					pointers[1] = baseaddress + 0x638B2C;
					pointers[2] = reinterpret_cast<uintptr_t>(g_kneeKPtr);
					pointers[3] = reinterpret_cast<uintptr_t>(g_kneeCPtr);
					pointers[4] = reinterpret_cast<uintptr_t>(g_kneeBPtr);
					pointers[5] = reinterpret_cast<uintptr_t>(g_kneeC1Ptr);
					pointers[6] = reinterpret_cast<uintptr_t>(g_satMulPtr);
					pointers[7] = reinterpret_cast<uintptr_t>(g_kneeC2Ptr);
					pointers[8] = reinterpret_cast<uintptr_t>(g_kneeC3Ptr);
					curveasm =
						"movd xmm0, dword ptr [rip + ?1]; cvtdq2ps xmm0, xmm0; divss xmm0, %1; mulss xmm0, xmm0; "
						"sub rsp, 0x10; movss dword ptr [rsp], xmm0; "
						"addss xmm0, xmm7; minss xmm0, %2; sqrtss xmm0, xmm0; movss dword ptr [rsp + 4], xmm0; "
						"movss xmm0, dword ptr [rsp]; maxss xmm0, xmm7; sqrtss xmm0, xmm0; maxss xmm0, %7; "
						"sqrtss xmm7, xmm7; mulss xmm7, dword ptr [rsp + 4]; divss xmm7, xmm0; mulss xmm7, dword ptr [rip + ?6]; minss xmm7, %2; "
						"comiss xmm7, dword ptr [rip + ?2]; jbe L; rcpss xmm0, xmm7; mulss xmm0, dword ptr [rip + ?3]; addss xmm0, dword ptr [rip + ?4]; jmp M; "
						"L: movss xmm0, dword ptr [rip + ?8]; mulss xmm0, xmm7; addss xmm0, dword ptr [rip + ?7]; mulss xmm0, xmm7; addss xmm0, dword ptr [rip + ?5]; "
						"M: mulss xmm7, xmm0; add rsp, 0x10; ";
				}
				else if (radialCurve && curveExp >= 1)
				{
					//xmm7 = x_norm^2 at the injection point; bring in the other
					//axis, build mag^2 = x^2+y^2 (clamped to 1), then
					//speed = |x| * mag^(exp-1)
					param_floats[1] = 255.0f;
					param_floats[2] = 1.0f;
					pointers[1] = baseaddress + 0x638B2C;
					curveasm = "movd xmm0, dword ptr [rip + ?1]; cvtdq2ps xmm0, xmm0; divss xmm0, %1; mulss xmm0, xmm0; addss xmm0, xmm7; minss xmm0, %2; sqrtss xmm7, xmm7; ";
					if (curveExp == 2)
						curveasm += "sqrtss xmm0, xmm0; ";
					if (curveExp >= 2)
						curveasm += "mulss xmm7, xmm0; ";
				}
				else if (curveExp == 1)
					curveasm = "sqrtss xmm7, xmm7; ";
				else if (curveExp == 3)
					curveasm = "sqrtss xmm0, xmm7; mulss xmm7, xmm0; ";
				else if (curveExp == 4)
					curveasm = "mulss xmm7, xmm7; ";
				curveasm += "mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0";
				ParametricASMJump(curveasm.c_str(), match, 0x8, 0x10);
			}

			//Same as above but for mouse (stock linear; xmm7 holds |x| here)
			match = FindOne("F3 0F 59 3D 9E 2D 32 00 80 3D 0A AA 36 00");
			param_floats[0] = log(framerate) / log(30.0f);
			pointers[0] = baseaddress + 0x611418;
			{
				std::string curveasm;
				if (curveExp >= 2)
				{
					curveasm = "movaps xmm0, xmm7; ";
					for (int i = 1; i < curveExp; i++)
						curveasm += "mulss xmm7, xmm0; ";
				}
				curveasm += "mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0";
				ParametricASMJump(curveasm.c_str(), match, 0, 0x8);
			}

			//Vertical axis: response curve AND framerate fix. The pad path adds
			//its turn every REAL frame, so without a fix the stick's vertical
			//camera speed multiplies with the framerate (4x too fast at 120).
			//Mouse input is a per-frame delta and framerate-neutral, so only
			//the pad branch gets the 30/framerate factor. xmm1 holds |y|; the
			//stock pad path squares it, the ini curve replaces that shape.
			{
				match = FindOne("84 C9 75 0A F3 0F 59 C9 F3 0F 59 D1 EB 10 F3 0F 10 05 ? ? ? ? F3 0F 59 C1 F3 0F 59 D0");
				{
					std::string curveasm;
					if (kneeCurve)
					{
						param_floats[0] = 255.0f;
						param_floats[1] = 1.0f;
						param_floats[2] = 1e-6f;
						pointers[0] = baseaddress + 0x638B28;
						pointers[1] = reinterpret_cast<uintptr_t>(g_kneeKPtr);
						pointers[2] = reinterpret_cast<uintptr_t>(g_kneeCPtr);
						pointers[3] = reinterpret_cast<uintptr_t>(g_kneeBPtr);
						pointers[4] = reinterpret_cast<uintptr_t>(g_kneeC1Ptr);
						pointers[5] = reinterpret_cast<uintptr_t>(g_satMulPtr);
						pointers[6] = reinterpret_cast<uintptr_t>(g_kneeC2Ptr);
						pointers[7] = reinterpret_cast<uintptr_t>(g_kneeC3Ptr);
						curveasm =
							"movaps xmm6, xmm1; mulss xmm6, xmm6; "
							"movd xmm0, dword ptr [rip + ?0]; cvtdq2ps xmm0, xmm0; divss xmm0, %0; mulss xmm0, xmm0; "
							"sub rsp, 0x10; movss dword ptr [rsp], xmm0; "
							"addss xmm0, xmm6; minss xmm0, %1; sqrtss xmm0, xmm0; movss dword ptr [rsp + 4], xmm0; "
							"movss xmm0, dword ptr [rsp]; maxss xmm0, xmm6; sqrtss xmm0, xmm0; maxss xmm0, %2; "
							"mulss xmm1, dword ptr [rsp + 4]; divss xmm1, xmm0; mulss xmm1, dword ptr [rip + ?5]; minss xmm1, %1; "
							"comiss xmm1, dword ptr [rip + ?1]; jbe L; rcpss xmm0, xmm1; mulss xmm0, dword ptr [rip + ?2]; addss xmm0, dword ptr [rip + ?3]; jmp M; "
							"L: movss xmm0, dword ptr [rip + ?7]; mulss xmm0, xmm1; addss xmm0, dword ptr [rip + ?6]; mulss xmm0, xmm1; addss xmm0, dword ptr [rip + ?4]; "
							"M: mulss xmm1, xmm0; add rsp, 0x10; ";
					}
					else if (radialCurve)
					{
						//xmm1 = |y|; xmm6 is scratch here (cleared right after
						//this block by the game). speed = |y| * mag^(exp-1)
						param_floats[0] = 255.0f;
						param_floats[1] = 1.0f;
						pointers[0] = baseaddress + 0x638B28;
						curveasm = "movaps xmm6, xmm1; mulss xmm6, xmm6; movd xmm0, dword ptr [rip + ?0]; cvtdq2ps xmm0, xmm0; divss xmm0, %0; mulss xmm0, xmm0; addss xmm0, xmm6; minss xmm0, %1; ";
						if (curveExp == 2)
							curveasm += "sqrtss xmm0, xmm0; ";
						if (curveExp >= 2)
							curveasm += "mulss xmm1, xmm0; ";
					}
					else if (curveExp >= 2)
					{
						curveasm = "movaps xmm0, xmm1; ";
						for (int i = 1; i < curveExp; i++)
							curveasm += "mulss xmm1, xmm0; ";
					}
					else if (curveExp == 0)
						curveasm = "mulss xmm1, xmm1; "; // stock quadratic shape
					param_floats[3] = 30.0f / framerate;
					curveasm += "mulss xmm1, %3; mulss xmm2, xmm1";
					ParametricASMJump(curveasm.c_str(), match, 0x4, 0xC);
				}
				if (curveExp > 0 || kneeCurve)
				{
					pointers[0] = baseaddress + 0x611418;
					std::string curveasm;
					if (curveExp >= 2)
					{
						curveasm = "movaps xmm0, xmm1; ";
						for (int i = 1; i < curveExp; i++)
							curveasm += "mulss xmm1, xmm0; ";
					}
					curveasm += "movss xmm0, dword ptr [rip + ?0]; mulss xmm0, xmm1; mulss xmm2, xmm0";
					ParametricASMJump(curveasm.c_str(), match, 0xE, 0x1A);
				}
			}

			//Fix controller camera speed (when transitioning to lock-on)
			match = FindOne("FF F3 44 0F 10 1D 42 F6 31 00 F3 41 0F 59 C3 44");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x61141C;
			ParametricASMJump("movss xmm11, dword ptr [rip + ?0]; mulss xmm11, %0", match, 0x1, 0xA);

			//Cycling 2d elements speed (i.e heat particles in the main menu, fire textures etc.) [ref: 0x002E4E50]
			match = FindOne("48 8B CB 75 0D 0F 28 D6 F3 0F 59 90 F8 01 00 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm2, %0", match, 0x8, 0x10);

			//Main menu delay frames before showing the intro cutscene again
			match = FindOne("00 48 8B 8C 24 40 1A 00 00 48 33 CC E8 FF 7D EE");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("mov ecx, dword ptr [rbx + 0x11C]; cvtsi2ss xmm10, ecx; mulss xmm10, %0; cvtss2si ecx, xmm10; mov dword ptr [rbx + 0x11C], ecx; mov rcx, qword ptr [rsp + 0x1a40]", match, 0x1, 0x9);

			//[ref: 0x002A1838]
			match = FindOne("E8 3B C3 FF FF F3 41 0F 58 84 3E B8 00 00 00 F3");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("addss xmm0, dword ptr [r14 + rdi + 0xB8]; mulss xmm0, %0", match, 0x5, 0xF);

			//Blue wavey effect
			match = FindOne("0F 29 B3 28 FF FF FF F3 44 0F 10 2D 55 E5 17 00");
			param_floats[0] = DecreaseFloatPrecision(4.0f * (30.0f / framerate), 8);
			ParametricASMJump("movss xmm13, %0", match, 0x7, 0x10);

			//Moogle dialog box
			match = FindOne("39 83 5C 01 00 00 40 0F B6 FF B9 01 00 00 00 0F");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("cvtsi2ss xmm11, eax; mulss xmm11, %0; cvtss2si eax, xmm11; cmp [rbx + 0x15C], eax", match, 0, 0x6);

			//Delay before next dialog when characters speak via the COM (i.e Kurasame at the beginning, with subtitles shown on the left side) Note: if you liked the previous speeded up behaviour you can select the fast dialog speed inside the options.
			match = FindOne("0F 4F C1 89 45 0C 48 8B 5C 24 58 48 8B 6C 24 68");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("cmovg eax, ecx; cvtsi2ss xmm11, eax; mulss xmm11, %0; cvtss2si eax, xmm11; mov [rbp + 0xC], eax", match, 0, 0x6);

			//Icons on the minimap that blink
			match = FindOne("00 89 45 A0 81 E1 0F 00 00 80 7D 07 FF C9 83 C9 F0 FF C1 48 63 C1 48 8D 55 88 48 8B CB 44 8B 74 85 00 48");
			uint32_t transparency_frames_count = 16.0f * framerate / 30.0f;
			transparency_frames_count &= 0xFFFFFFFE; //This has to be an even number
			auto transparency_frames = trampoline->RawSpace(transparency_frames_count);
			for (uint32_t i = 0; i < transparency_frames_count / 2; i++)
			{
				transparency_frames[i] = static_cast<std::byte>(TransparencySplineInterpolation(static_cast<float>(i) / (transparency_frames_count / 2 - 1)));
				transparency_frames[transparency_frames_count - 1 - i] = transparency_frames[i];
			}
			constants[0] = transparency_frames_count;
			pointers[0] = reinterpret_cast<uintptr_t>(transparency_frames);
			ParametricASMJump("mov eax, ecx; mov r14d, $0; xor edx, edx; div r14d; lea rax, [rip + ?0]; add rax, rdx; xor ecx, ecx; mov cl, byte ptr [rax]; mov r14d, ecx; lea rdx, [rbp - 0x78]; mov rcx, rbx;", match, 0x4, 0x22);

			//Handle edge case that works differently for some reason (26 frames of animation instead of 16)
			match = FindOne("0D D3 97 1A 00 45 69 C9 00 00 00 19 41 81 C9 FF");
			transparency_frames_count = 26.0f * framerate / 30.0f;
			transparency_frames = trampoline->RawSpace(transparency_frames_count);
			for (uint32_t i = 0; i < transparency_frames_count; i++)
			{
				transparency_frames[i] = static_cast<std::byte>(TransparencyLinearInterpolation(static_cast<float>(i) / (transparency_frames_count - 1)));
			}
			constants[0] = transparency_frames_count;
			pointers[0] = baseaddress + 0x63CD00;
			pointers[1] = reinterpret_cast<uintptr_t>(transparency_frames);
			ParametricASMJump("mov eax, dword ptr [rip + ?0]; mov r9d, $0; xor edx, edx; div r9d; lea rax, [rip + ?1]; add rax, rdx; mov dl, byte ptr [rax]; mov r9d, edx; shl r9d, 0x18; mov edx, dword ptr [rsp + 0x120];", match, 0x5, 0xC);
			match = FindOne("6C 94 1A 00 45 69 C0 00 00 00 19 41 81 C8 FF FF"); //Also handle the else branch
			ParametricASMJump("mov eax, dword ptr [rip + ?0]; mov r9d, $0; xor edx, edx; div r9d; lea rax, [rip + ?1]; add rax, rdx; mov dl, byte ptr [rax]; mov r9d, edx; shl r9d, 0x18; mov edx, dword ptr [rsp + 0x120];", match, 0x5, 0xC);

			//Color circles pulsating (TODO: Understand how they work and patch them instead of making them pretend they're running @30fps)
			match = FindOne("83 F8 01 41 B0 01 B8 89 88 88 88 75 0C 45 8D 4B");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mov eax, 0x88888889; cvtsi2ss xmm11, r11d; mulss xmm11, %0; cvtss2si r11d, xmm11", match, 0x6, 0xB);

			//Fix animated water texture speed
			match = FindOne("F3 44 0F 59 15 4F DA 1B 00 0F 28 D1 85 C9 0F 84");
			param_floats[0] = (0.033333331f * 30.0f) / framerate;
			ParametricASMJump("mulss xmm10, %0", match, 0, 0x9);

			//Fix info panels on the left side of the screen disappearing too quickly (i.e Character used Magic, Obtained Phantoma etc.)
			match = FindOne("4C 8D 34 90 8B 55 80 85 D2 41 C6 46 1A 00 41 0F");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("mov edx, dword ptr [rbp - 0x80]; cvtsi2ss xmm11, edx; mulss xmm11, %0; cvtss2si edx, xmm11; test edx, edx;", match, 0x4, 0x9);

			//Projectile speed general fix (This is the holy grail of fixes, but it's also one of the worst manual x86 code ever written.) Note: the first parameter passed to the function in which this is injected (sub_140287C20) gets copied to rdi. Rdi + 0x54, 58 and 5C contains the coordinate offset for the next frame, which I'd need to adjust according to the framerate, however since the functions that call this one are many and different between each other, the compiler decided to sometimes have temporary registers that holds those values (3 of the registers in the xmm6-12 range) and sometimes reload them from memory. This code should handle every possible combination of those, but it's really ugly. The only other solution would be to manually patch each function before the call, but that would require a lot of redirections for doing basically the same things.
			match = FindOne("7A B0 01 4C 8D 9C 24 C0 00 00 00 49 8B 5B 38 49 8B 73 40 49 8B 7B 48 41 0F 28 73 F0 41 0F 28 7B");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movaps xmm6, xmmword ptr [r11 - 0x10]; movaps xmm7, xmmword ptr [r11 - 0x20]; movaps xmm8, xmmword ptr [r11 - 0x30]; movss xmm2, %0; comiss xmm6, dword ptr [rdi + 0x54]; je A; comiss xmm6, dword ptr [rdi + 0x58]; je A; comiss xmm6, dword ptr [rdi + 0x5C]; jne B; A: mulss xmm6, xmm2; B: comiss xmm7, dword ptr [rdi + 0x54]; je C; comiss xmm7, dword ptr [rdi + 0x58]; je C; comiss xmm7, dword ptr [rdi + 0x5C]; jne D; C: mulss xmm7, xmm2; D: comiss xmm8, dword ptr [rdi + 0x54]; je E; comiss xmm8, dword ptr [rdi + 0x58]; je E; comiss xmm8, dword ptr [rdi + 0x5C]; jne F; E: mulss xmm8, xmm2; F: comiss xmm9, dword ptr [rdi + 0x54]; je G; comiss xmm9, dword ptr [rdi + 0x58]; je G; comiss xmm9, dword ptr [rdi + 0x5C]; jne H; G: mulss xmm9, xmm2; H: comiss xmm10, dword ptr [rdi + 0x54]; je I; comiss xmm10, dword ptr [rdi + 0x58]; je I; comiss xmm10, dword ptr [rdi + 0x5C]; jne J; I: mulss xmm10, xmm2; J: comiss xmm11, dword ptr [rdi + 0x54]; je K; comiss xmm11, dword ptr [rdi + 0x58]; je K; comiss xmm11, dword ptr [rdi + 0x5C]; jne L; K: mulss xmm11, xmm2; L: comiss xmm12, dword ptr [rdi + 0x54]; je M; comiss xmm12, dword ptr [rdi + 0x58]; je M; comiss xmm12, dword ptr [rdi + 0x5C]; jne N; M: mulss xmm12, xmm2; N: movss xmm3, dword ptr [rdi + 0x54]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x54], xmm3; movss xmm3, dword ptr [rdi + 0x58]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x58], xmm3; movss xmm3, dword ptr [rdi + 0x5C]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x5C], xmm3; mov rdi, [r11 + 0x48];", match, 0x13, 0x26);

			//New setup for frame counter based fixes
			match = FindOne("48 89 3B C6 43 08 01 48 8B 5C 24 40 48 83 C4 20");
			auto interleavedincrement = trampoline->Pointer<float>();
			auto propagatecounters = trampoline->Pointer<uint8_t>();
			auto reset_list = trampoline->Pointer<uint8_t>(); //Used as an interleaved cycle, to avoid desync
			*reset_list = 1;
			uint8_t damage_and_audio_triggers_count = 20;
			auto damage_and_audio_triggers = reinterpret_cast<uint64_t*>(trampoline->RawSpace(damage_and_audio_triggers_count * sizeof(uint64_t)));
			uint8_t floatcountersptrs_count = 20;
			auto floatcountersptrs = reinterpret_cast<uint64_t*>(trampoline->RawSpace(floatcountersptrs_count * sizeof(uint64_t)));
			constants[0] = damage_and_audio_triggers_count;
			constants[1] = floatcountersptrs_count;
			param_floats[0] = 30.0f / framerate;
			param_floats[1] = 1.0f;
			pointers[0] = reinterpret_cast<uintptr_t>(interleavedincrement);
			pointers[1] = reinterpret_cast<uintptr_t>(propagatecounters);
			pointers[2] = reinterpret_cast<uintptr_t>(reset_list);
			pointers[3] = reinterpret_cast<uintptr_t>(damage_and_audio_triggers);
			pointers[4] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			ParametricASMJump("movss xmm2, dword ptr [rip + ?0]; addss xmm2, %0; comiss xmm2, %1; mov byte ptr [rip + ?1], 0; jb A; subss xmm2, %1; mov byte ptr [rip + ?1], 1; lea rax, [rip + ?4]; xor rbx, rbx; C: mov qword ptr [rax + rbx * 8], 0; inc rbx; cmp bl, $1; jl C; neg byte ptr [rip + ?2]; js A; lea rax, [rip + ?3]; xor rbx, rbx; B: mov qword ptr [rax + rbx * 8], 0; inc rbx; cmp bl, $0; jl B; A: movss dword ptr [rip + ?0], xmm2; mov rbx, qword ptr [rsp + 0x40]", match, 0x7, 0xC);

			auto stats = reinterpret_cast<uint32_t*>(trampoline->RawSpace(9 * sizeof(uint32_t)));
			memset(stats, 0, 9 * sizeof(uint32_t));
			g_stats = stats;


			//$ Fire projectile damage trigger to rts elements only once
			if (!disableTriggerDedup)
			{
			match = FindOne("40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 18 FE FF FF 48 81 EC");
			constants[0] = damage_and_audio_triggers_count;
			pointers[0] = reinterpret_cast<uintptr_t>(damage_and_audio_triggers);
			pointers[1] = reinterpret_cast<uintptr_t>(reset_list);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[0]);
			pointers[3] = reinterpret_cast<uintptr_t>(&stats[5]);
			ParametricASMJump("lea rax, [rip + ?0]; xor r10, r10; B: cmp r10b, $0; jge G; cmp qword ptr [rax + r10 * 8], 0; je A; cmp rbx, qword ptr [rax + r10 * 8]; je C; inc r10; jmp B; C: mov eax, 1; ret; G: inc dword ptr [rip + ?2]; jmp D; A: mov byte ptr [rip + ?1], 1; mov qword ptr [rax + r10 * 8], rbx; cmp dword ptr [rip + ?3], r10d; jge D; mov dword ptr [rip + ?3], r10d; D: push rbp; push rbx; push rsi; push rdi;", match, 0, 0x5);

			//Remove audio trigger duplicates (ideally there should be a proper fix, like for the triggers above, for now it just mutes them)
			match = FindOne("41 FF 46 10 49 89 76 08 49 8D 4D 18 48 8B 01 FF");
			constants[0] = damage_and_audio_triggers_count;
			pointers[0] = reinterpret_cast<uintptr_t>(damage_and_audio_triggers);
			pointers[1] = reinterpret_cast<uintptr_t>(reset_list);
			pointers[2] = reinterpret_cast<uintptr_t>(match.get<void>(0x2E));
			pointers[3] = reinterpret_cast<uintptr_t>(&stats[5]);
			pointers[4] = reinterpret_cast<uintptr_t>(&stats[1]);
			ParametricASMJump("inc dword ptr [r14+10h]; mov [r14+8], rsi; cmp rax, 0x20; je F; push r8; push r10; lea r8, [rip + ?0]; xor r10, r10; A: cmp qword ptr [r8 + r10 * 8], r11; je D; inc r10; cmp r10b, $0; jl A; xor r10, r10; B: cmp r10b, $0; jge G; cmp qword ptr [r8 + r10 * 8], 0; jne C; mov qword ptr [r8 + r10 * 8], r11; cmp dword ptr [rip + ?3], r10d; jge E; mov dword ptr [rip + ?3], r10d; jmp E; C: inc r10; jmp B; G: inc dword ptr [rip + ?4]; E: pop r10; pop r8; mov byte ptr [rip + ?1], 1; jmp F; D: xorps xmm0, xmm0; pop r10; pop r8; lea rax, [rip + ?2]; jmp rax; F: nop", match, 0, 0x8);
			}

			if (!disableCounterDedup)
			{
			//Gameplay fixes #1 (i.e guards falling into the ground below when dropping from the ship at the beginning of the game)[ref:0x0013D75C, different approach used]
			match = FindOne("8B 43 08 F3 0F 10 04 88 F3 0F 58 05 3C DE 20 00");
			constants[0] = floatcountersptrs_count;
			constants[1] = baseaddress + 0x574CA0; //Whenever it's supposed to be a proper frame counter instead of a random increase, this value is @rsp + 0x60
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[2]);
			param_floats[0] = 1.0f;
			param_floats[1] = 10.0f;
			ParametricASMJump("mov r13, $1; cmp qword ptr [rsp + 0x60], r13; je F; movss xmm1, dword ptr [rsp + 0x10]; comiss xmm1, %1; jae E; comiss xmm1, %0; jb E; F: lea rbx, [rax + rcx * 4]; lea r13, [rip + ?0]; xor r15, r15; A: cmp qword ptr [r13 + r15 * 8], rbx; je D; inc r15; cmp r15b, $0; jl A; addss xmm0, %0; xor r15, r15; B: cmp r15b, $0; jge G; cmp qword ptr [r13 + r15 * 8], 0; jne C; mov qword ptr [r13 + r15 * 8], rbx; cmp dword ptr [rip + ?1], r15d; jge D; mov dword ptr [rip + ?1], r15d; jmp D; C: inc r15; jmp B; G: inc dword ptr [rip + ?2]; jmp D; E: addss xmm0, %0; D: nop", match, 0x8, 0x10);

			//Unknown (likely Gameplay fixes #2 due to proximity) [ref: 0x0013D86C]
			match = FindOne("00 00 00 F3 0F 10 04 88 F3 0F 5C 05 78 DD 20 00");
			constants[0] = floatcountersptrs_count;
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[3]);
			param_floats[0] = 1.0f;
			ParametricASMJump("lea rbx, [rax + rcx * 4]; lea r13, [rip + ?0]; xor r15, r15; A: cmp qword ptr [r13 + r15 * 8], rbx; je D; inc r15; cmp r15b, $0; jl A; subss xmm0, %0; xor r15, r15; B: cmp r15b, $0; jge G; cmp qword ptr [r13 + r15 * 8], 0; jne C; mov qword ptr [r13 + r15 * 8], rbx; cmp dword ptr [rip + ?1], r15d; jge D; mov dword ptr [rip + ?1], r15d; jmp D; C: inc r15; jmp B; G: inc dword ptr [rip + ?2]; D: nop", match, 0x8, 0x10);

			//Various timings, used mainly in cutscenes but not exclusively [ref: 0x00127D90]
			match = FindOne("2F C8 76 04 C6 41 2C 01 F3 0F 5C 0D 93 34 22 00");
			constants[0] = floatcountersptrs_count;
			param_floats[0] = 1.0f;
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[4]);
			ParametricASMJump("push rax; push rdx; push r14; lea rax, [rcx + 0x38]; lea rdx, [rip + ?0]; xor r14, r14; A: cmp qword ptr [rdx + r14 * 8], rax; je D; inc r14; cmp r14b, $0; jl A; subss xmm1, %0; xor r14, r14; B: cmp r14b, $0; jge G; cmp qword ptr [rdx + r14 * 8], 0; jne C; mov qword ptr [rdx + r14 * 8], rax; cmp dword ptr [rip + ?1], r14d; jge D; mov dword ptr [rip + ?1], r14d; jmp D; C: inc r14; jmp B; G: inc dword ptr [rip + ?2]; D: pop r14; pop rdx; pop rax;", match, 0x8, 0x10);

			//Script command 0x179: per-frame countdown that keeps a screen layer/fade
			//visible for N frames ([rcx+0x38]--) while flagging the script context as
			//waiting ([rcx+0x2C]=1). Unpatched it expires framerate/30 times too fast,
			//letting the next cutscene start while the previous one is still on screen.
			//Deduplicated per counter address, same as the timings above. [new fix]
			match = FindOne("0F 2F C1 76 19 F3 0F 5C 05 ? ? ? ? F3 0F 11 41 38 80 88 E8 05 00 00 10 C6 41 2C 01 C3");
			constants[0] = floatcountersptrs_count;
			param_floats[0] = 1.0f;
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[7]);
			ParametricASMJump("push rax; push rdx; push r14; lea rax, [rcx + 0x38]; lea rdx, [rip + ?0]; xor r14, r14; A: cmp qword ptr [rdx + r14 * 8], rax; je D; inc r14; cmp r14b, $0; jl A; subss xmm0, %0; xor r14, r14; B: cmp r14b, $0; jge G; cmp qword ptr [rdx + r14 * 8], 0; jne C; mov qword ptr [rdx + r14 * 8], rax; cmp dword ptr [rip + ?1], r14d; jge D; mov dword ptr [rip + ?1], r14d; jmp D; C: inc r14; jmp B; G: inc dword ptr [rip + ?2]; D: pop r14; pop rdx; pop rax; movss dword ptr [rcx + 0x38], xmm0", match, 0x5, 0x12);

			//In-engine demo scenes (named command VM: Wait/Fade/ChangeMotion/... registry).
			//The "Wait" command advances an int16 frame counter at [rcx+0x24] every real
			//frame and compares it against a duration authored in 30fps frames, so demo
			//waits expire framerate/30 times too early. Deduplicated per counter address
			//(the shared list works for any address, float or int). [new fix]
			match = FindOne("66 FF 41 24 0F BF 49 24 33 C0 3B 4A 08 0F 9D C0 C3");
			constants[0] = floatcountersptrs_count;
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[8]);
			ParametricASMJump("push rax; push rdx; push r14; lea rax, [rcx + 0x24]; lea rdx, [rip + ?0]; xor r14, r14; A: cmp qword ptr [rdx + r14 * 8], rax; je D; inc r14; cmp r14b, $0; jl A; inc word ptr [rcx + 0x24]; xor r14, r14; B: cmp r14b, $0; jge G; cmp qword ptr [rdx + r14 * 8], 0; jne C; mov qword ptr [rdx + r14 * 8], rax; cmp dword ptr [rip + ?1], r14d; jge D; mov dword ptr [rip + ?1], r14d; jmp D; C: inc r14; jmp B; G: inc dword ptr [rip + ?2]; D: pop r14; pop rdx; pop rax; movsx ecx, word ptr [rcx + 0x24]", match, 0, 0x8);

			//Same int16 frame counter inside the demo "TargetEffect" command handler.
			match = FindOne("66 FF 41 24 0F BF 41 24 F3 0F 10 46 10 66 0F 6E C8");
			constants[0] = floatcountersptrs_count;
			pointers[0] = reinterpret_cast<uintptr_t>(floatcountersptrs);
			pointers[1] = reinterpret_cast<uintptr_t>(&stats[6]);
			pointers[2] = reinterpret_cast<uintptr_t>(&stats[8]);
			ParametricASMJump("push rax; push rdx; push r14; lea rax, [rcx + 0x24]; lea rdx, [rip + ?0]; xor r14, r14; A: cmp qword ptr [rdx + r14 * 8], rax; je D; inc r14; cmp r14b, $0; jl A; inc word ptr [rcx + 0x24]; xor r14, r14; B: cmp r14b, $0; jge G; cmp qword ptr [rdx + r14 * 8], 0; jne C; mov qword ptr [rdx + r14 * 8], rax; cmp dword ptr [rip + ?1], r14d; jge D; mov dword ptr [rip + ?1], r14d; jmp D; C: inc r14; jmp B; G: inc dword ptr [rip + ?2]; D: pop r14; pop rdx; pop rax; movsx eax, word ptr [rcx + 0x24]", match, 0, 0x8);
			}

			//In game timer
			match = FindOne("00 00 75 71 80 3D CC 8D 49 00 00 75 68 8B 05 8D");
			constants[0] = baseaddress + 0x1CF05D;
			pointers[0] = baseaddress + 0x667DBF;
			pointers[1] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 0; jz B; A: mov rcx, $0; jmp rcx; B: cmp byte ptr [rip + ?1], 1; jne A;", match, 0x4, 0xD);

			//Fix for QueryPerformanceCounter skewing the result
			match = FindOne("72 00 F3 0F 5E 35 EE DE 52 00 F3 0F 58 35 3A DC");
			param_floats[0] = framerate / 30.0f;
			pointers[0] = baseaddress + 0x580068;
			ParametricASMJump("mulss xmm6, %0; divss xmm6, [rip + ?0]", match, 0x2, 0xA);

			//Bonus/Malus duration
			match = FindOne("74 34 0F B7 06 66 41 03 C5 66 89 06 66 83 F8 5A");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("movzx eax, word ptr [rsi]; cmp byte ptr [rip + ?0], 1; jne A; add ax, r13w; A: nop;", match, 0x2, 0x9);

			//RTS missions bases regen speed
			match = FindOne("00 FF C1 48 85 C0 75 08 8B 96 0C 02 00 00 EB 06");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc ecx; A: test rax, rax;", match, 0x1, 0x6);

			//RTS missions troop respawn time
			match = FindOne("00 00 66 85 C0 7E 0A 66 FF C8 66 89 86 BC 01 00");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec ax; A: mov [rsi + 0x1BC], ax;", match, 0x7, 0x11);

			//RTS requests countdown
			match = FindOne("88 1F 05 00 00 FF C8 41 0F 48 C4 89 85 A0 00 00");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec eax; A: test eax, eax; cmovs eax, r12d;", match, 0x5, 0xB);

			//RTS Troop reshooting time
			match = FindOne("7E 22 66 FF C9 66 89 8B D8 01 00 00 0F BF C1 74");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec cx; A: mov [rbx + 0x1D8], cx;", match, 0x2, 0xC);
			match = FindOne("66 FF C8 66 89 83 D8 01 00 00 98 0F 85 BD 03 00");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec ax; A: mov [rbx + 0x1D8], ax;", match, 0, 0xA);

			//RTS Projectile duration
			match = FindOne("F0 66 89 B3 BC 01 00 00 48 8B 87 A0 01 00 00 48");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("cvtsi2ss xmm11, esi; mulss xmm11, %0; cvtss2si esi, xmm11; mov [rbx + 0x1BC], si", match, 0x1, 0x8);
			match = FindOne("66 0F 6E C0 0F 5B C0 0F 2F 05 1E 9E 12 00 76 1E");
			param_floats[0] = (framerate / 30.0f) * 40.0f;
			ParametricASMJump("movss xmm10, %0; comiss xmm0, xmm10", match, 0x7, 0xE);

			//$ Fire projectile damage trigger to player/ai enemies only once (fixes Deuce's sphere from being incredibly OP, between other things)
			match = FindOne("48 85 D2 0F 84 B6 02 00 00 56 57 41 57 48 81 EC");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("test rdx, rdx; jnz A; ret; A: cmp byte ptr [rip + ?0], 1; je B; ret; B: nop", match, 0, 0x9);

			//2d mouth texture and eyes blinking timings
			match = FindOne("40 53 48 83 EC 30 48 8B 81 30 05 00 00 48 8B D9");
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			ParametricASMJump("cmp byte ptr [rip + ?0], 1; je A; ret; A: push rbx; sub rsp, 0x30", match, 0, 0x6);

			//General frame counter based actions #1 (bullets range (Ace's cards, rocket launcher guy), charged attacks, Nine's jump etc.)
			FindAll("66 FF ? 86 00 00 00", 0).for_each_result([propagatecounters](auto found)
			mutable
			{
				pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
				byte_patch patch[1] = {
					{.offset = 11, .val = *found.get<uint8_t>(2) },
				};
				ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc word ptr [rdi + 0x86]; A: nop", found, 0, 0x7, patch, 1);
			});
			//#2, with inc and mov instead of just inc for whatever reason
			FindAll("66 FF ? 66 89 ? 86 00 00 00", 0).for_each_result([propagatecounters](auto found) // movzx X, word ptr [Y + 0x88] : X = general purpose 32 bit register, Y = general purpose 64 bit register
			mutable
			{
				auto inc_reg_byte = *found.get<uint8_t>(2);
				auto mov_reg_byte = *found.get<uint8_t>(5);
				if ((inc_reg_byte & 0xF8) == 0xC0) //make sure it's an inc and not a dec
				{
					if ((mov_reg_byte & 0xC0) == 0x80) //make sure it's a valid mov
					{
						auto value_reg = inc_reg_byte & 0x7;
						if (value_reg == ((mov_reg_byte >> 3) & 0x7)) //makes sure it's referring to the same register
						{
							pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
							byte_patch patch[2] = {
								{.offset = 11, .val = inc_reg_byte },
								{.offset = 14, .val = mov_reg_byte }
							};
							ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc ax; A: mov [rdi + 0x86], ax;", found, 0, 0xA, patch, 2);
						}
					}
				}
			});

			//HP regen (and poison effect) speed
			match = FindOne("99 83 E2 7F 03 C2 C1 F8 07 03 F0 EB 02 03 F3 8B");
			constants[0] = 128 * (framerate / 30.0f);
			ParametricASMJump("mov r8d, $0; cdq; idiv r8d;", match, 0, 0x9);
			match = FindOne("C6 99 83 E2 7F 03 C2 C1 F8 07 85 C0 74 7F 44 8B");
			constants[0] = 128 * (framerate / 30.0f);
			ParametricASMJump("mov r8d, $0; cdq; idiv r8d;", match, 0x1, 0xA);


			//Specific characters moveset fixes

			//Queen's Divine Judgement ability gauge's cost (per frame)
			match = FindOne("D0 74 0F F7 DA 45 33 C0 48 8B CF E8 D0 60 00 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("xor r8d, r8d; cvtsi2ss xmm11, edx; mulss xmm11, %0; cvtss2si edx, xmm11; neg edx", match, 0x3, 0x8);

			//Queen's Divine Judgement rotation speed
			match = FindOne("F3 0F 10 05 2C 65 2D 00 F3 0F 58 87 B8 00 00 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm10, %0; mulss xmm1, xmm10; mulss xmm0, xmm10; addss xmm0, dword ptr [rdi + 0xB8];", match, 0x8, 0x10);

			//Nine's jump (and high jump) travel distance (take into account accumulating floating point errors when adjusting the values)
			match = FindOne("87 FC 00 00 00 F3 0F 58 53 08 F3 0F 58 4B 04 F3 0F 58 03 F3 0F 11 03 F3");
			param_floats[0] = 20.0f / (framerate - 10.0f);
			ParametricASMJump("mulss xmm2, %0; mulss xmm1, %0; mulss xmm0, %0; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx]", match, 0x5, 0x13);
			match = FindOne("10 03 F3 0F 58 87 FC 00 00 00 F3 0F 58 53 08 F3");
			param_floats[0] = 20.0f / (framerate - 10.0f);
			ParametricASMJump("movss xmm0, dword ptr [rdi + 0xFC]; mulss xmm2, %0; mulss xmm1, %0; mulss xmm0, %0; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx]", match, 0x2, 0x14);

			//Trey's raining arrows
			match = FindOne("0F 10 83 FC 00 00 00 F3 0F 58 93 94 00 00 00 F3");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm2, %0; mulss xmm1, %0; mulss xmm0, %0; addss xmm2, dword ptr [rbx+ 0x94]", match, 0x7, 0xF);
			match = FindOne("F3 0F 58 93 94 00 00 00 F3 0F 58 8B 90 00 00 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm2, %0; mulss xmm1, %0; mulss xmm0, %0; addss xmm2, dword ptr [rbx+ 0x94]", match, 0, 0x8);

			//Rocket Launcher guy projectile speed (instead of being set every time the function is called, it's only done once, so it needs to be reset for the next cycle)
			match = FindOne("00 00 48 8B 8D 10 01 00 00 48 33 CC E8 4F 50 E8");
			param_floats[0] = framerate / 30.0f;
			ParametricASMJump("mov rcx, qword ptr [rbp + 0x110]; movss xmm3, dword ptr [rdi + 0x54]; mulss xmm3, %0; movss dword ptr [rdi + 0x54], xmm3; movss xmm3, dword ptr [rdi + 0x58]; mulss xmm3, %0; movss dword ptr [rdi + 0x58], xmm3; movss xmm3, dword ptr [rdi + 0x5C]; mulss xmm3, %0; movss dword ptr [rdi + 0x5C], xmm3;", match, 0x2, 0x9);

			//Fire RF (and potentially similar attacks) bullet elapsed range [ref: 0x002A13A8]
			match = FindOne("05 93 57 2C 00 F3 41 0F 10 84 06 B8 00 00 00 0F");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm0, dword ptr [r14 + rax + 0xB8]; mulss xmm0, %0", match, 0x5, 0xF);

			//Fire RF (and potentially similar attacks) bullet speed
			match = FindOne("0F 10 43 10 F3 0F 58 53 08 F3 0F 58 4B 04 F3 0F 58 03 F3 0F 11 03 F3 0F");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm13, %0; mulss xmm2, xmm13; mulss xmm1, xmm13; mulss xmm0, xmm13; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx];", match, 0x4, 0x12);

			//Deuce flute energy sphere horizontal orbit
			match = FindOne("F3 0F 58 05 A8 5B 2C 00 0F 2F C1 F3 0F 11 83 FC");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x57FBE8;
			ParametricASMJump("movss xmm4, %0; mulss xmm4, dword ptr [rip + ?0]; addss xmm0, xmm4", match, 0, 0x8);

			//Deuce flute energy sphere vertical orbit
			match = FindOne("04 01 00 00 F3 0F 58 05 34 5B 2C 00 0F 2F C1 F3");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x57FBA8;
			ParametricASMJump("movss xmm4, %0; mulss xmm4, dword ptr [rip + ?0]; addss xmm0, xmm4;", match, 0x4, 0xC);

			//Deuce flute energy sphere bouncing pattern
			auto increasestartvalue = FindOne("01 00 00 76 0B 48 C7 83 00 01 00 00 00 00 20 41");
			Patch<float>(increasestartvalue.get<void>(0xC), (30.0f / framerate) * 10.0f);
			match = FindOne("0F 10 83 00 01 00 00 F3 0F 5C 05 C5 5C 2C 00 F3");
			param_floats[0] = pow(30.0f / framerate, 2);
			ParametricASMJump("subss xmm0, %0", match, 0x7, 0xF);

			//Deuce flute energy sphere when following targets (speed and amplitude)
			match = FindOne("C8 80 E1 01 F3 44 0F 11 43 54 F3 44 0F 11 53 58");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm9, xmm7; mulss xmm9, xmm1; mulss xmm8, %0; mulss xmm9, %0; mulss xmm10, %0; movss dword ptr [rbx + 0x54], xmm8; movss dword ptr [rbx + 0x58], xmm10; movss dword ptr [rbx + 0x5C], xmm9", match, 0x4, 0x20);
			match = FindOne("15 73 61 2C 00 48 8D 55 B8 48 8B CB 0F 28 DA E8");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm2, %0; lea rdx, [rbp - 0x48]; mov rcx, rbx", match, 0x5, 0xC);

			//Deuce flute energy sphere when going back to Deuce
			match = FindOne("0F B6 0D C0 ED 39 00 F3 44 0F 11 43 54 F3 44 0F");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("lea rdx, [rbx + 0x44]; mov eax, 0x20; and cl, 1; mulss xmm8, %0; mulss xmm9, %0; mulss xmm10, %0; movss dword ptr [rbx + 0x54], xmm8; movss dword ptr [rbx + 0x58], xmm10; movss dword ptr [rbx + 0x5C], xmm9", match, 0x7, 0x25);

			//Enemy grenade (thrown by generals) bouncing pattern
			match = FindOne("00 F3 41 0F 11 06 F3 41 0F 11 4E 04 89 8F 20 01");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("mulss xmm1, %0; movss dword ptr [r14 + 0x4], xmm1", match, 0x6, 0xC);
			FindAll("F3 0F 5C 05 ? ? 2E 00 4C 8D 87 AC 00 00 00 48 8D", 2).for_each_result([framerate](auto found)
			mutable
			{
				param_floats[0] = pow(30.0f / framerate, 2) * 1.9f;
				ParametricASMJump("subss xmm0, %0", found, 0, 0x8);
			});
			FindAll("76 ? C7 87 00 01 00 00 00 00 F0 41 EB ? F3 41", 2).for_each_result([framerate](auto found)
			mutable
			{
				Patch<float>(found.get<void>(0x8), (30.0f / framerate) * 30.0f);
			});
			FindAll("00 0F 2F 05 ? ? 2E 00 F3 0F 11 87 00 01 00 00", 2).for_each_result([framerate](auto found)
			mutable 
			{
				param_floats[0] = (30.0f / framerate) * 30.0f;
				ParametricASMJump("comiss xmm0, %0", found, 0x1, 0x8);
			});

			//Enemy grenade range
			match = FindOne("87 00 01 00 00 F3 41 0F 10 56 08 F3 41 0F 10 4E"); //case 3
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm2, dword ptr [r14 + 0x8]; movss xmm1, dword ptr [r14 + 0x4]; movss xmm0, dword ptr [r14]; mulss xmm2, %0; mulss xmm0, %0; addss xmm2, dword ptr [rdx + 0x8]; addss xmm1, dword ptr [rdx + 0x4]; addss xmm0, dword ptr [rdx]", match, 0x5, 0x24);
			match = FindOne("00 F3 41 0F 10 54 24 08 F3 41 0F 10 4C 24 04 49"); //case 4
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("movss xmm2, dword ptr [r12 + 0x8]; movss xmm1, dword ptr [r12 + 0x4]; movss xmm0, dword ptr [r12]; mulss xmm2, %0; mulss xmm0, %0; addss xmm2, dword ptr [r15 + 0x8]; addss xmm1, dword ptr [r15 + 0x4]; addss xmm0, dword ptr [r15]; mov rdx, r15", match, 0x1, 0x29);

			//RTS turret animation timings
			match = FindOne("7E 06 41 83 EE 02 EB 06 41 BE"); //Delay before rising
			ParametricASMJump("cmp word ptr [rdi + 0x1B0], 0; jle A; dec word ptr [rdi + 0x1B0]; jmp B; A: sub r14d, 2; B: nop", match, 0x2, 0xE);
			match = FindOne("00 0F 5B C0 F3 0F 59 05 B8 84 12 00 F3 0F 5E C7"); //Adjust tilt when rising
			param_floats[0] = 3.14159f * (30.0f / framerate);
			ParametricASMJump("mulss xmm0, %0", match, 0x4, 0xC);
			match = FindOne("0F 5B C0 F3 0F 59 05 E9 87 12 00 F3 0F 5E 05 49"); //Adjust tilt when falling (and set the delay)
			constants[0] = 45 * (framerate / 30.0f - 1);
			param_floats[0] = 3.14159f * (30.0f / framerate);
			ParametricASMJump("mov word ptr [rsi + 0x1B0], $0; mulss xmm0, %0", match, 0x3, 0xB);

		}

		const float fovoverride = GetPrivateProfileIntW(L"FOV", L"FOVPercentage", 0, wcModulePath) / 100.0f;
		if (fovoverride > 0.0f)
		{
			LogF("[FOV] applying %.2f", fovoverride);
			auto keepcutscenefov = trampoline->Pointer<int8_t>();
			*keepcutscenefov = GetPrivateProfileIntW(L"FOV", L"KeepCutsceneFOV", 1, wcModulePath);

			match = FindOne("0F 59 35 45 41 1D 00 44 0F 29 50 A8 44 0F 29 58");
			auto fovmul = trampoline->Pointer<float>();
			*fovmul = fovoverride;
			pointers[0] = reinterpret_cast<uintptr_t>(keepcutscenefov);
			pointers[1] = baseaddress + 0x658F70;
			pointers[2] = reinterpret_cast<uintptr_t>(fovmul);
			ParametricASMJump("movaps xmmword ptr [rax - 0x58], xmm10; cmp byte ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 1; jz B; A: mulss xmm6, dword ptr [rip + ?2]; B: nop", match, 0x7, 0xC);
			const int dynFov = GetPrivateProfileIntW(L"Camera", L"DynamicFOVPercent", 0, wcModulePath);
			g_pitchFovPct = GetPrivateProfileIntW(L"Camera", L"PitchFOVPercent", 0, wcModulePath);
			g_fovMulPtr = fovmul;
			g_fovBase = fovoverride;
			g_tuneFovPct = static_cast<int>(fovoverride * 100.0f + 0.5f);
			if (dynFov > 0)
			{
				g_dynFovPct = dynFov;
				LogF("[Camera] dynamic FOV: +%d%% at full turn speed", dynFov);
			}
		}

		LogF("=== FFT0HD Unlocker init done ===");
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceMovies", 0, wcModulePath) != 0)
			g_movieBase = baseaddress;
		if (g_skipIntroVideos)
			g_introBase = baseaddress;
		g_gameBase = baseaddress;
		StartStatsWatcher();
		StartSoundTraceWatcher();
		StartMovieTraceWatcher();
		StartIntroSkipWatcher();
		g_autoSkipSplash = GetPrivateProfileIntW(L"Intro", L"AutoSkipSplash", 0, wcModulePath) != 0;
		g_camFree = GetPrivateProfileIntW(L"Camera", L"FreeCameraDistance", -9999, wcModulePath);
		g_camLock = GetPrivateProfileIntW(L"Camera", L"LockCameraDistance", -9999, wcModulePath);
		g_padTurnPct = GetPrivateProfileIntW(L"Camera", L"PadTurnSpeedPercent", -1, wcModulePath);
		g_mouseTurnPct = GetPrivateProfileIntW(L"Camera", L"MouseTurnSpeedPercent", -1, wcModulePath);
		g_vertTurnPct = GetPrivateProfileIntW(L"Camera", L"VerticalTurnSpeedPercent", -1, wcModulePath);
		if (g_camFree != -9999 || g_camLock != -9999 || g_padTurnPct >= 0 || g_mouseTurnPct >= 0 || g_vertTurnPct >= 0)
			LogF("[Camera] overrides: free=%d lock=%d padTurn=%d%% mouseTurn=%d%% vertTurn=%d%%", g_camFree, g_camLock, g_padTurnPct, g_mouseTurnPct, g_vertTurnPct);
		g_tuneWindow = GetPrivateProfileIntW(L"Camera", L"TuneWindow", 0, wcModulePath) != 0;
		StartCameraWatcher();
		StartDynamicFovWatcher();
		StartTuneWindow();
		StartBootAutoSkipWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"BootScan", 0, wcModulePath) != 0)
			StartBootScanWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"BootTrace", 0, wcModulePath) != 0)
			StartBootTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceSticks", 0, wcModulePath) != 0)
			StartStickTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TracePitch", 0, wcModulePath) != 0)
			StartPitchTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceMove", 0, wcModulePath) != 0)
			StartMoveTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceBattle", 0, wcModulePath) != 0)
			StartBattleTraceWatcher();
		g_watchAiEvent = GetPrivateProfileIntW(L"Diagnostics", L"WatchAiEvent", 0, wcModulePath) != 0;
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceBossPos", 0, wcModulePath) != 0)
			StartBossPosTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceScriptMove", 0, wcModulePath) != 0)
			StartScriptMoveTraceWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"TraceWatchdog", 0, wcModulePath) != 0)
			StartWatchdogTraceWatcher();
		{
			const int tierScan = GetPrivateProfileIntW(L"Diagnostics", L"TierScan", 0, wcModulePath);
			if (tierScan == 2)
				StartTierProbeWatcher();
			else if (tierScan != 0)
				StartTierScanWatcher();
		}
		if (GetPrivateProfileIntW(L"Diagnostics", L"WriteWatch", 0, wcModulePath) != 0)
			StartWriteWatch();
		StartAutoTierWatcher();

		} // end try
		catch (const std::exception& e)
		{
			LogF("[Patch] ABORTED after a missing/failed signature: %s", e.what());
			MessageBox(
				NULL,
				(LPCWSTR)L"FFT0HD Unlocker: a code signature didn't match this version of the game, so patching was stopped to avoid a crash.\nSee the .log file next to the .ini for the exact signature that failed.",
				(LPCWSTR)L"FFT0HD Unlocker",
				MB_ICONWARNING | MB_OK
			);
		}
	}
	else
	{
		MessageBox(
			NULL,
			(LPCWSTR)L"Couldn't locate the required functions in keystone.dll for the patch.\nMake sure you are using the included keystone.dll in this folder from the github release.",
			(LPCWSTR)L"keystone.dll Error",
			MB_ICONWARNING | MB_OK
		);
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		hDLLModule = hinstDLL;
	}
	return TRUE;
}
