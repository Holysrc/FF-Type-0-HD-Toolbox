// Regression cases for the actual helpers extracted from source/Patch.cpp.
#include <cstdint>
#include <vector>
#include <cassert>
#include <cstdio>
#include <cstring>
static uintptr_t g_gameBase;
static uint32_t frame;
static volatile uint32_t* g_scriptFrames=&frame;
static void (*g_nativeEventQuery)(uintptr_t);
static void LogF(const char*,...) {}

#include "script_motion_helpers.hpp"

static uint32_t nativeBits;
static void NativeQuery(uintptr_t ctx) { *reinterpret_cast<float*>(ctx+0x30)=(nativeBits&2)?1.f:0.f; }
int main() {
 std::vector<uint8_t> game(0x667e30),table(0x300),actors(0x2000),ai(0x5a8),contexts(0x5000);
 g_gameBase=(uintptr_t)game.data();uintptr_t a=(uintptr_t)actors.data(), b=(uintptr_t)ai.data(), q=(uintptr_t)contexts.data(), q2=q+0xa0;
 *reinterpret_cast<uintptr_t*>(g_gameBase+0x667e20)=(uintptr_t)table.data();
 *reinterpret_cast<uintptr_t*>(table.data()+0x18+6*8)=a;
 *reinterpret_cast<uint16_t*>(a+0x360)=0x200b; // deliberately not Vajra
 *reinterpret_cast<int*>(a+0x5c8)=1286;
 *reinterpret_cast<int8_t*>(b+8)=6;
 auto setup=[&](uintptr_t c) { *reinterpret_cast<uintptr_t*>(c+8)=0x123400;*reinterpret_cast<uint32_t*>(c+0x28)=10988;
  *reinterpret_cast<float*>(c+0x34)=6;*reinterpret_cast<float*>(c+0x38)=1;*reinterpret_cast<float*>(c+0x3c)=1; };
 setup(q);setup(q2);
 g_nativeEventQuery=NativeQuery;g_scriptMotionWindow=4;
 auto reset=[&] { for(auto& p:g_scriptMotionPulses)p={};for(auto& r:g_scriptMotionReaders)r={};nativeBits=0;frame=99;setup(q);setup(q2);g_scriptMotionMask=0xFFFFFFFFu; };
 auto result=[&](uintptr_t c) { QueryScriptMotionCompletion(c);return *reinterpret_cast<float*>(c+0x30); };
 auto capture=[&] { *reinterpret_cast<uint32_t*>(b+0x1a0)=2;CaptureScriptMotionCompletion(b);nativeBits=0; };
 for(uint32_t age=0;age<=4;++age) {
  reset();assert(result(q)==0);frame=100;capture();frame+=age;
  assert(result(q)==1);assert(result(q)==1); // repeated reads in same render
  ++frame;assert(result(q)==0);++frame;assert(result(q)==0); // no duplicate delivery
 }
 reset();assert(result(q)==0);frame=100;capture();frame=105;assert(result(q)==0); // expired
 reset();assert(result(q)==0);frame=150;capture();frame=151;assert(result(q)==0); // inactive reader
 reset();frame=100;capture();frame=101;assert(result(q)==0);++frame;assert(result(q)==0); // new reader
 reset();assert(result(q)==0);assert(result(q2)==0);frame=100;capture();frame=101;
 assert(result(q)==1);assert(result(q2)==1); // independent readers
 reset();assert(result(q)==0);assert(result(q2)==0);frame=100;nativeBits=2;assert(result(q)==1);capture();frame=101;
 assert(result(q)==0);assert(result(q2)==1); // native observation does not steal other's pulse
 reset();assert(result(q)==0);frame=100;capture();++frame;*reinterpret_cast<int*>(a+0x5c8)=1288;assert(result(q)==0);
 reset();assert(result(q)==0);frame=100;capture();++frame;++*reinterpret_cast<uint32_t*>(a+0x40);assert(result(q)==0); // same clip, new request
 reset();assert(result(q)==0);frame=100;capture();++frame;++*reinterpret_cast<uint32_t*>(q+0x28);assert(result(q)==0); // new query
 reset();assert(result(q)==0);frame=100;capture();++frame;++*reinterpret_cast<uintptr_t*>(q+8);assert(result(q)==0); // script reuse
 reset();assert(result(q)==0);frame=100;capture();++frame;*reinterpret_cast<uintptr_t*>(table.data()+0x18+6*8)=a+0x1000;assert(result(q)==0);
 *reinterpret_cast<uintptr_t*>(table.data()+0x18+6*8)=a;
 reset();assert(result(q)==0);frame=100;capture();++frame;*reinterpret_cast<float*>(q+0x3c)=0;assert(result(q)==0); // other bit
 reset();assert(result(q)==0);frame=100;*reinterpret_cast<uint32_t*>(b+0x1a0)=1;CaptureScriptMotionCompletion(b);++frame;assert(result(q)==0);
 reset();frame=0xfffffffe;assert(result(q)==0);++frame;capture();frame=1;assert(result(q)==1); // frame wrap
 reset();assert(result(q)==0);uintptr_t collision=q+0x4000;setup(collision);assert(result(collision)==0);
 frame=100;capture();++frame;assert(result(q)==0); // hash collision loses history safely
 // bit 0 (landing keyframe) recovery, same rules as bit 1
 auto captureBit=[&](uint32_t bit) { *reinterpret_cast<uint32_t*>(b+0x1a0)=1u<<bit;CaptureScriptMotionCompletion(b);nativeBits=0; };
 for(uint32_t age=0;age<=4;++age) {
  reset();*reinterpret_cast<float*>(q+0x3c)=0;assert(result(q)==0);frame=100;captureBit(0);frame+=age;
  assert(result(q)==1);assert(result(q)==1);++frame;assert(result(q)==0);
 }
 reset();*reinterpret_cast<float*>(q+0x3c)=0;assert(result(q)==0);frame=100;captureBit(0);frame=105;assert(result(q)==0); // expired
 // a bit-1 pulse never satisfies a bit-0 reader and vice versa
 reset();*reinterpret_cast<float*>(q+0x3c)=0;assert(result(q)==0);frame=100;captureBit(1);++frame;assert(result(q)==0);
 reset();assert(result(q)==0);frame=100;captureBit(0);++frame;assert(result(q)==0);
 // both bits raised in one render: two readers of the same script/PC (different bits) each recover once
 reset();*reinterpret_cast<float*>(q2+0x3c)=0;assert(result(q)==0);assert(result(q2)==0);frame=100;
 *reinterpret_cast<uint32_t*>(b+0x1a0)=3;CaptureScriptMotionCompletion(b);++frame;assert(result(q)==1);assert(result(q2)==1);
 ++frame;assert(result(q)==0);assert(result(q2)==0);
 // mask: bit 0 excluded -> native behaviour for bit 0, bit 1 still recovered
 reset();g_scriptMotionMask=2;*reinterpret_cast<float*>(q2+0x3c)=0;assert(result(q)==0);assert(result(q2)==0);frame=100;
 *reinterpret_cast<uint32_t*>(b+0x1a0)=3;CaptureScriptMotionCompletion(b);++frame;assert(result(q)==1);assert(result(q2)==0);
 // out-of-range bit argument and other selectors are left to the native handler
 reset();*reinterpret_cast<float*>(q+0x3c)=32;assert(result(q)==0);frame=100;*reinterpret_cast<uint32_t*>(b+0x1a0)=0xFFFFFFFFu;CaptureScriptMotionCompletion(b);++frame;assert(result(q)==0);
 reset();*reinterpret_cast<float*>(q+0x38)=0;assert(result(q)==0);frame=100;captureBit(1);++frame;assert(result(q)==0);
 puts("PASS: phases, repeated reads, expiry, polling lifetime, native observation, independent consumers, actor/motion/request/script/PC reset, other bits, wrap, collision fallback, bit0 landing, per-bit independence, mask, selector/bit range");
}
