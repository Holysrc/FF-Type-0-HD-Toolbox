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

// Real logo skip ([Intro] SkipIntroLogos=1): the boot splash sequencer keeps a
// tick counter at base+0x6C4BCC (+2 per 30Hz tick, clamped by the game) and a
// deque of pending slides (begin/end pointers at base+0x63D1D8/0x63D1E0).
// Slides advance when the counter passes their thresholds, so while the deque
// is non-empty we slam the counter to a huge value: every threshold is
// instantly exceeded and the whole slide show resolves in a few frames.
static bool g_skipIntroLogos = false;

static void StartSlideSkipWatcher()
{
	if (!g_skipIntroLogos || !g_gameBase)
		return;
	std::thread([] {
		const ULONGLONG start = GetTickCount64();
		bool announced = false;
		while (!g_bootPhaseOver)
		{
			Sleep(50);
			if (GetTickCount64() - start > 60000)
				break;
			if (*reinterpret_cast<volatile uint8_t*>(g_gameBase + 0x655ECC) != 0)
				break;
			const uint64_t qbegin = *reinterpret_cast<volatile uint64_t*>(g_gameBase + 0x63D1D8);
			const uint64_t qend = *reinterpret_cast<volatile uint64_t*>(g_gameBase + 0x63D1E0);
			if (!qbegin || qend == qbegin)
				continue;
			*reinterpret_cast<volatile uint32_t*>(g_gameBase + 0x6C4BCC) = 0x7FF00000;
			if (!announced)
			{
				announced = true;
				LogF("[SkipLogos] slide queue detected, fast-forwarding boot timer");
			}
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
			if (now - lastPress < 400)
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
const uint8_t POINTERS_ARRAY_SIZE = 5;
const uint8_t FLOATS_ARRAY_SIZE = 5;

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
			match = FindOne("24 0F 28 CE F3 0F 59 4C 24 20 F3 0F 11 43 1C F3");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x658F70;
			pointers[1] = baseaddress + 0x6D1CEC;
			ParametricASMJump("mulss xmm1, dword ptr [rsp + 0x20]; cmp dword ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 0; jnz B; A: mulss xmm1, %0; mulss xmm6, %0; B: nop", match, 0x4, 0xA);

			//Controlled character turning speed (a bit broken above 90 fps) [ref: 0x00006734 to 0x00006744]
			match = FindOne("F3 0F 59 49 40 F3 0F 59 CA F3 0F 59 51 34 F3 0F 59 0D 1F C4 3A 00");
			param_floats[0] = 15.0f / framerate;
			ParametricASMJump("movss xmm1, dword ptr [rcx + 0x40]; movss xmm2, dword ptr [rcx + 0x34]; mulss xmm1, %0", match, 0, 0x16);

			//First cutscene slow-motion walk speed [ref: 0x00006998]
			match = FindOne("20 5B C3 F3 0F 10 41 04 F3 0F 58 05 69 BE 3A 00");
			param_floats[0] = 30.0f / framerate;
			ParametricASMJump("addss xmm0, %0", match, 0x8, 0x10);

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

			//Fix controller camera speed (orbital) for controller
			match = FindOne("C7 F3 0F 59 C7 0F 28 F8 F3 0F 59 3D AC 2D 32 00");
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x61141C;
			ParametricASMJump("mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0", match, 0x8, 0x10);

			//Same as above but for mouse
			match = FindOne("F3 0F 59 3D 9E 2D 32 00 80 3D 0A AA 36 00");
			param_floats[0] = log(framerate) / log(30.0f);
			pointers[0] = baseaddress + 0x611418;
			ParametricASMJump("mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0", match, 0, 0x8);

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
			param_floats[0] = fovoverride;
			pointers[0] = reinterpret_cast<uintptr_t>(keepcutscenefov);
			pointers[1] = baseaddress + 0x658F70;
			ParametricASMJump("movaps xmmword ptr [rax - 0x58], xmm10; cmp byte ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 1; jz B; A: mulss xmm6, %0; B: nop", match, 0x7, 0xC);
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
		g_skipIntroLogos = GetPrivateProfileIntW(L"Intro", L"SkipIntroLogos", 0, wcModulePath) != 0;
		StartBootAutoSkipWatcher();
		StartSlideSkipWatcher();
		if (GetPrivateProfileIntW(L"Diagnostics", L"BootScan", 0, wcModulePath) != 0)
			StartBootScanWatcher();

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
