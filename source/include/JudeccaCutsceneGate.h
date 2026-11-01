#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace JudeccaCutsceneGate {
// Standard uniforms and matching auxiliary resource banks from the game's
// cut7558/getPCModel4. IDs are character-model IDs, not party-slot numbers.
inline constexpr int standInResources[] = {3004,3026,3023,3022,3016,3020,3024,3019,3017,3021,3018,3025};
inline constexpr int standInBanks[] = {91,102,99,98,92,96,100,95,93,97,94,101};
// cut7555 uses these PC animations but explicitly loads only2400: ordinary
// party actors already have the low-numbered clips. CMDEF actors do not.
inline constexpr int standInClips[] = {7,67,68,69,71,2400};

inline int ChooseStandIn(const int* models)
{
    if (!models) return -1;
    for (int model = 0; model < 12; ++model)
        if (models[0] != model && models[1] != model && models[2] != model) return model;
    return -1;
}

inline bool StandInScope(int armedScene, int currentScene, int stage)
{
    // First runtime candidate: the already verified final-boss intro only.
    return armedScene == 7555 && currentScene == armedScene && stage >= 5 && stage <= 8;
}

// Exact captured IF(CMD5F()>2) through CMD12(scene), including branch labels.
// PCs are command-parser PCs (+6 after the nested CMD5F command header).
inline constexpr uint8_t boss[] = {
    0x11,0x00,0x22,0x00,0xA3,0x00,0xF2,0x05,0xFC,0x0F,0x00,0x00,
    0x84,0x00,0x36,0x01,0x41,0x00,0x0A,0x00,0x22,0x01,0xFC,0x0F,
    0x04,0x00,0x23,0x00,0x44,0x10
};
inline constexpr uint8_t approach[] = {
    0x11,0x00,0x42,0x00,0xA3,0x00,0xF2,0x05,0xFC,0x0F,0x00,0x00,
    0x84,0x00,0x36,0x01,0x41,0x00,0x08,0x00,0x11,0x00,0x22,0x00,
    0xA3,0x00,0x22,0x3B,0xFC,0x0F,0x00,0x00,0x44,0x00,0xD6,0x06,
    0x41,0x00,0x0A,0x00,0x22,0x01,0xFC,0x0F,0x04,0x00,0x23,0x00,
    0x44,0x6A
};

inline int Match(uint32_t pc, const uint8_t* bytes, size_t size,
                 float threshold, float scene, float secondaryZero)
{
    if (!bytes || threshold != 2.0f) return 0;
    if (pc == 0x64E && size == sizeof(boss) && scene == 7555.0f &&
        std::memcmp(bytes, boss, sizeof(boss)) == 0) return 7555;
    if (pc == 0x203A && size == sizeof(approach) && scene == 7553.0f &&
        secondaryZero == 0.0f && std::memcmp(bytes, approach, sizeof(approach)) == 0) return 7553;
    return 0;
}

inline bool CanOverride(float alive, const int* models)
{
    if ((alive != 1.0f && alive != 2.0f) || !models) return false;
    int present = 0;
    for (int i = 0; i < 3; ++i) {
        // -1 is the native empty-slot result, not an invalid character model.
        if (models[i] == -1) continue;
        if (models[i] < 0 || models[i] > 13) return false;
        ++present;
        for (int j = 0; j < i; ++j) if (models[i] == models[j]) return false;
    }
    return present >= alive;
}

inline bool SkipMissingActor(int channel, const char* name, int armedScene,
                             int currentScene, int stage, unsigned emptySlots)
{
    // A negative channel means "default scene actor" to CMD4/CMD219. Use an
    // out-of-range POSITIVE channel for an explicitly named missing PC instead.
    // Native commands then do nothing, including animation waits.
    if (!name || (armedScene != 7553 && armedScene != 7555) || currentScene != armedScene ||
        stage < 4 || stage > 11) return false;
    if (std::strcmp(name, "PC_0") != 0 && std::strcmp(name, "PC_1") != 0 &&
        std::strcmp(name, "PC_2") != 0) return false;
    const int slot = name[3] - '0';
    // Empty slots also have real actor objects: captured PC_1 resolved to ch1,
    // class/modelFFFF, HP0/0. They accept animation queues that never complete.
    // Only skip a matching party channel known empty at the eligibility check.
    return channel == -1 || (channel == slot && (emptySlots & (1u << slot)) != 0);
}
}
