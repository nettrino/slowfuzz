//===- FuzzerMutate.cpp - Mutate a test input -----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Mutate a test input.
//===----------------------------------------------------------------------===//

#include <cstring>
#include <random>
#include <chrono>

#include "FuzzerCorpus.h"
#include "FuzzerDefs.h"
#include "FuzzerExtFunctions.h"
#include "FuzzerMutate.h"
#include "FuzzerOptions.h"

namespace fuzzer {

const size_t Dictionary::kMaxDictSize;

static void PrintASCII(const Word &W, const char *PrintAfter) {
  PrintASCII(W.data(), W.size(), PrintAfter);
}

MutationDispatcher::MutationDispatcher(Random &Rand, Random &TrueRand,
                                       const FuzzingOptions &Options)
    : Rand(Rand), TrueRand(TrueRand), Options(Options) {
  DefaultMutators.insert(
      DefaultMutators.begin(),
      {
          {&MutationDispatcher::Mutate_EraseBytes, "0"},
          {&MutationDispatcher::Mutate_InsertByte, "1"},
          {&MutationDispatcher::Mutate_InsertRepeatedBytes,
           "2"},
          {&MutationDispatcher::Mutate_ChangeByte, "3"},
          {&MutationDispatcher::Mutate_ChangeBit, "4"},
          {&MutationDispatcher::Mutate_ShuffleBytes, "5"},
          {&MutationDispatcher::Mutate_ChangeASCIIInteger, "6"},
          {&MutationDispatcher::Mutate_ChangeBinaryInteger, "7"},
          {&MutationDispatcher::Mutate_CopyPart, "8"},
          {&MutationDispatcher::Mutate_CrossOver, "9"},
          {&MutationDispatcher::Mutate_AddWordFromManualDictionary,
           "10"},
          {&MutationDispatcher::Mutate_AddWordFromTemporaryAutoDictionary,
           "11"},
          {&MutationDispatcher::Mutate_AddWordFromPersistentAutoDictionary,
           "12"},
      });

  // if (EF->LLVMFuzzerCustomMutator)
    // Mutators.push_back({&MutationDispatcher::Mutate_Custom, "Custom"});
  // else
    Mutators = DefaultMutators;
  // if (EF->LLVMFuzzerCustomCrossOver)
    // Mutators.push_back(
        // {&MutationDispatcher::Mutate_CustomCrossOver, "CustomCrossOver"});
    MutatorScores = std::vector<uint64_t>(DefaultMutators.size(), 0);
    MutatorBucketScores = std::vector<uint64_t>(Options.ScoreBuckets + 1, 0);
}

static char RandCh(Random &Rand) {
  if (Rand.RandBool()) return Rand(256);
  const char *Special = "!*'();:@&=+$,/?%#[]012Az-`~.\xff\x00";
  return Special[Rand(sizeof(Special) - 1)];
}

/* FIXME */
size_t
MutationDispatcher::Mutate_Custom(uint8_t *Data, size_t Size,
                                  int64_t MutStart,
                                  size_t MaxSize) {
  return EF->LLVMFuzzerCustomMutator(Data, Size, MaxSize, Rand.Rand());
}

int MutationDispatcher::GetMutatorsSize() {
  return Mutators.size();
}

void
MutationDispatcher::IncreaseMutatorScore(uint32_t idx) {
  assert(idx <= DefaultMutators.size() && "invalid index");
  MutatorScores[idx]++;
}

void
MutationDispatcher::IncreaseMutatorBucketScore(uint32_t bucket_idx) {
  // FIXME
  if (bucket_idx > Options.ScoreBuckets)
    bucket_idx = bucket_idx % Options.ScoreBuckets;
  assert(bucket_idx <= Options.ScoreBuckets && "invalid bucket index");
  MutatorBucketScores[bucket_idx]++;
}


uint64_t
MutationDispatcher::GetMutatorScore(uint32_t idx) {
  if (Options.DeathMode == 0)
    return 0;
  assert(idx <= DefaultMutators.size() && "invalid score index");
  return MutatorScores[idx];
}

std::vector<uint64_t>
MutationDispatcher::GetMutatorBuckets() {
  return MutatorBucketScores;
}


size_t
MutationDispatcher::Mutate_CustomCrossOver(uint8_t *Data,
                                           size_t Size,
                                           int64_t MutStart,
                                           size_t MaxSize) {
  if (!Corpus || Corpus->size() < 2 || Size == 0)
    return 0;
    // return std::make_tuple(0, 0);
  size_t Idx = Rand(Corpus->size());
  const Unit &Other = (*Corpus)[Idx];
  if (Other.empty())
    return 0;
    // return std::make_tuple(0, 0);
  MutateInPlaceHere.resize(MaxSize);
  auto &U = MutateInPlaceHere;
  size_t NewSize = EF->LLVMFuzzerCustomCrossOver(
      Data, Size, Other.data(), Other.size(), U.data(), U.size(), Rand.Rand());
  if (!NewSize)
    return 0;
    // return std::make_tuple(0, 0);
  assert(NewSize <= MaxSize && "CustomCrossOver returned overisized unit");
  memcpy(Data, U.data(), NewSize);
  return 0;
  // return std::make_tuple(0, NewSize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_ShuffleBytes(uint8_t *Data,
                                        size_t Size,
                                        int64_t MutStart,
                                        size_t MaxSize) {
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  assert(Size);
  size_t ShuffleAmount =
      Rand(std::min(Size, (size_t)8)) + 1; // [1,8] and <= Size.
  size_t ShuffleStart = Rand(Size - ShuffleAmount);
  if (MutStart != -1 && MutStart < Size - ShuffleAmount)
    ShuffleStart = MutStart;
  assert(ShuffleStart + ShuffleAmount <= Size);
  std::random_shuffle(Data + ShuffleStart, Data + ShuffleStart + ShuffleAmount,
                      Rand);
  return std::make_tuple(ShuffleStart, ShuffleAmount * sizeof(uint8_t), Size);
}
std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_EraseBytes(uint8_t *Data,
                                      size_t Size,
                                      int64_t MutStart,
                                      size_t MaxSize) {
  assert(Size);
  if (Size == 1) return std::make_tuple(0, 0, 0);
  size_t N = Rand(Size / 2) + 1;
  assert(N < Size);
  size_t Idx = Rand(Size - N + 1);
  if (MutStart != -1 && MutStart < Size - N + 1)
    Idx = MutStart;
  // Erase Data[Idx:Idx+N].
  memmove(Data + Idx, Data + Idx + N, Size - Idx - N);
  // Printf("Erase: %zd %zd => %zd; Idx %zd\n", N, Size, Size - N, Idx);
  return std::make_tuple(Idx, N, Size - N);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_InsertByte(uint8_t *Data,
                                      size_t Size,
                                      int64_t MutStart,
                                      size_t MaxSize) {
  if (Size >= MaxSize) return std::make_tuple(0, 0, 0);
  size_t Idx = Rand(Size + 1);
  if (MutStart != -1 && MutStart < Size + 1)
    Idx = MutStart;
  // Insert new value at Data[Idx].
  memmove(Data + Idx + 1, Data + Idx, Size - Idx);
  if (Options.OnlyDict) {
    Data[Idx] = ManualChrDictionary[TrueRand(ManualChrDictionary.size())].GetW().data()[0];
  } else {
    Data[Idx] = RandCh(Rand);
  }
  return std::make_tuple(Idx, 1, Size + 1);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_InsertRepeatedBytes(uint8_t *Data,
                                               size_t Size,
                                               int64_t MutStart,
                                               size_t MaxSize) {
  const size_t kMinBytesToInsert = 3;
  if (Size + kMinBytesToInsert >= MaxSize) return std::make_tuple(0, 0, 0);
  size_t MaxBytesToInsert = std::min(MaxSize - Size, (size_t)128);
  size_t N = Rand(MaxBytesToInsert - kMinBytesToInsert + 1) + kMinBytesToInsert;
  assert(Size + N <= MaxSize && N);
  size_t Idx = Rand(Size + 1);
  if (MutStart != -1 && MutStart < Size + 1)
    Idx = MutStart;
  // Insert new values at Data[Idx].
  memmove(Data + Idx + N, Data + Idx, Size - Idx);
  // Give preference to 0x00 and 0xff.
  uint8_t Byte = Rand.RandBool() ? Rand(256) : (Rand.RandBool() ? 0 : 255);
  for (size_t i = 0; i < N; i++) {
    if (Options.OnlyDict) {
      Data[Idx + i] = ManualChrDictionary[TrueRand(ManualChrDictionary.size())].GetW().data()[0];
    } else {
      Data[Idx + i] = Byte;
    }
  }
  return std::make_tuple(Idx, N * sizeof(uint8_t), Size + N);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_ChangeByte(uint8_t *Data,
                                      size_t Size,
                                      int64_t MutStart,
                                      size_t MaxSize) {
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  size_t Idx = Rand(Size);
  if (MutStart != -1 && MutStart < Size)
    Idx = MutStart;
  if (Options.OnlyDict) {
    //FIXME
    Data[Idx] = ManualChrDictionary[TrueRand(ManualChrDictionary.size())].GetW().data()[0];
  } else {
    Data[Idx] = RandCh(Rand);
  }
  return std::make_tuple(Idx, 1, Size);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_ChangeBit(uint8_t *Data,
                                     size_t Size,
                                     int64_t MutStart,
                                     size_t MaxSize) {
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  size_t Idx = Rand(Size);
  if (MutStart != -1 && MutStart < Size)
    Idx = MutStart;
  Data[Idx] ^= 1 << Rand(8);
  return std::make_tuple(Idx, 1, Size);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_AddWordFromManualDictionary(uint8_t *Data,
                                                       size_t Size,
                                                       int64_t MutStart,
                                                       size_t MaxSize) {
  return AddWordFromDictionary(ManualDictionary, Data, Size, MutStart, MaxSize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_AddWordFromTemporaryAutoDictionary(uint8_t *Data,
                                                              size_t Size,
                                                              int64_t MutStart,
                                                              size_t MaxSize) {
  return AddWordFromDictionary(TempAutoDictionary, Data, Size, MutStart, MaxSize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_AddWordFromPersistentAutoDictionary(uint8_t *Data,
                                                               size_t Size,
                                                               int64_t MutStart,
                                                               size_t MaxSize) {
  return AddWordFromDictionary(PersistentAutoDictionary, Data, Size, MutStart, MaxSize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::AddWordFromDictionary(Dictionary &D,
                                          uint8_t *Data,
                                          size_t Size,
                                          int64_t MutStart,
                                          size_t MaxSize) {
  size_t Idx;

  if (Size > MaxSize)  return std::make_tuple(0, 0, 0);
  if (D.empty())  return std::make_tuple(0, 0, 0);
  DictionaryEntry &DE = D[Rand(D.size())];
  const Word &W = DE.GetW();
  bool UsePositionHint = DE.HasPositionHint() &&
                         DE.GetPositionHint() + W.size() < Size && Rand.RandBool();
  if (Rand.RandBool()) {  // Insert W.
    if (Size + W.size() > MaxSize)  return std::make_tuple(0, 0, 0);
    size_t Idx = UsePositionHint ? DE.GetPositionHint() : Rand(Size + 1);
    if (MutStart != -1 && MutStart < Size)
      Idx = MutStart;
    memmove(Data + Idx + W.size(), Data + Idx, Size - Idx);
    memcpy(Data + Idx, W.data(), W.size());
    Size += W.size();
  } else {  // Overwrite some bytes with W.
    if (W.size() > Size)  return std::make_tuple(0, 0, 0);
    Idx = UsePositionHint ? DE.GetPositionHint() : Rand(Size - W.size());
    memcpy(Data + Idx, W.data(), W.size());
  }
  DE.IncUseCount();
  CurrentDictionaryEntrySequence.push_back(&DE);
  return std::make_tuple(Idx, W.size(), Size);
}

// Overwrites part of To[0,ToSize) with a part of From[0,FromSize).
// Returns ToSize.
std::tuple<size_t, size_t, size_t>
MutationDispatcher::CopyPartOf(const uint8_t *From,
                               size_t FromSize,
                               uint8_t *To,
                               size_t ToSize,
                               int64_t MutStart) {
  // Copy From[FromBeg, FromBeg + CopySize) into To[ToBeg, ToBeg + CopySize).
  size_t ToBeg = Rand(ToSize);
  if (MutStart != -1 && MutStart < ToSize)
    ToBeg = MutStart;
  size_t CopySize = Rand(ToSize - ToBeg) + 1;
  assert(ToBeg + CopySize <= ToSize);
  CopySize = std::min(CopySize, FromSize);
  size_t FromBeg = Rand(FromSize - CopySize + 1);
  assert(FromBeg + CopySize <= FromSize);
  memmove(To + ToBeg, From + FromBeg, CopySize);
  return std::make_tuple(ToBeg, CopySize, ToSize);
}

// Inserts part of From[0,ToSize) into To.
// Returns new size of To on success or 0 on failure.
std::tuple<size_t, size_t, size_t>
MutationDispatcher::InsertPartOf(const uint8_t *From,
                                 size_t FromSize,
                                 uint8_t *To,
                                 size_t ToSize,
                                 int64_t MutStart,
                                 size_t MaxToSize) {
  if (ToSize >= MaxToSize) return std::make_tuple(0, 0, 0);
  size_t AvailableSpace = MaxToSize - ToSize;
  size_t MaxCopySize = std::min(AvailableSpace, FromSize);
  size_t CopySize = Rand(MaxCopySize) + 1;
  size_t FromBeg = Rand(FromSize - CopySize + 1);
  assert(FromBeg + CopySize <= FromSize);
  size_t ToInsertPos = Rand(ToSize + 1);
  if (MutStart != -1 && MutStart < ToSize + 1)
    ToInsertPos = MutStart;
  assert(ToInsertPos + CopySize <= MaxToSize);
  size_t TailSize = ToSize - ToInsertPos;
  if (To == From) {
    MutateInPlaceHere.resize(MaxToSize);
    memcpy(MutateInPlaceHere.data(), From + FromBeg, CopySize);
    memmove(To + ToInsertPos + CopySize, To + ToInsertPos, TailSize);
    memmove(To + ToInsertPos, MutateInPlaceHere.data(), CopySize);
  } else {
    memmove(To + ToInsertPos + CopySize, To + ToInsertPos, TailSize);
    memmove(To + ToInsertPos, From + FromBeg, CopySize);
  }
  return std::make_tuple(ToInsertPos, CopySize, ToSize + CopySize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_CopyPart(uint8_t *Data,
                                    size_t Size,
                                    int64_t MutStart,
                                    size_t MaxSize) {
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  if (Rand.RandBool())
    return CopyPartOf(Data, Size, Data, Size, MutStart);
  else
    return InsertPartOf(Data, Size, Data, Size, MutStart, MaxSize);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_ChangeASCIIInteger(uint8_t *Data,
                                              size_t Size,
                                              int64_t MutStart,
                                              size_t MaxSize) {
  size_t Idx = 0;
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  size_t B = Rand(Size);
  if (MutStart != -1 && MutStart < Size)
    B = MutStart;
  while (B < Size && !isdigit(Data[B])) B++;
  if (B == Size) return std::make_tuple(0, 0, 0);
  size_t E = B;
  while (E < Size && isdigit(Data[E])) E++;
  assert(B < E);
  // now we have digits in [B, E).
  // strtol and friends don't accept non-zero-teminated data, parse it manually.
  uint64_t Val = Data[B] - '0';
  for (size_t i = B + 1; i < E; i++)
    Val = Val * 10 + Data[i] - '0';

  // Mutate the integer value.
  switch(Rand(5)) {
    case 0: Val++; break;
    case 1: Val--; break;
    case 2: Val /= 2; break;
    case 3: Val *= 2; break;
    case 4: Val = Rand(Val * Val); break;
    default: assert(0);
  }
  // Just replace the bytes with the new ones, don't bother moving bytes.
  for (size_t i = B; i < E; i++) {
    Idx = E + B - i - 1;
    assert(Idx >= B && Idx < E);
    Data[Idx] = (Val % 10) + '0';
    Val /= 10;
  }
  return std::make_tuple(B, E - B, Size);
}

// uint8_t  Bswap(uint8_t x)  { return x; }
// uint16_t Bswap(uint16_t x) { return __builtin_bswap16(x); }
// uint32_t Bswap(uint32_t x) { return __builtin_bswap32(x); }
// uint64_t Bswap(uint64_t x) { return __builtin_bswap64(x); }

template<class T>
std::tuple<size_t, size_t, size_t>
ChangeBinaryInteger(uint8_t *Data,
                    size_t Size,
                    int64_t MutStart,
                    Random &Rand) {
  if (Size < sizeof(T)) return std::make_tuple(0, 0, 0);
  size_t Off = Rand(Size - sizeof(T) + 1);
  if (MutStart != -1 && MutStart < Size - sizeof(T) + 1)
    Off = MutStart;
  assert(Off + sizeof(T) <= Size);
  T Val;
  memcpy(&Val, Data + Off, sizeof(Val));
  T Add = Rand(21);
  Add -= 10;
  if (Rand.RandBool())
    Val = Bswap(T(Bswap(Val) + Add));  // Add assuming different endiannes.
  else
    Val = Val + Add;                   // Add assuming current endiannes.
  if (Add == 0 || Rand.RandBool())     // Maybe negate.
    Val = -Val;
  memcpy(Data + Off, &Val, sizeof(Val));
  return std::make_tuple(Off, sizeof(Val), Size);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_ChangeBinaryInteger(uint8_t *Data,
                                               size_t Size,
                                               int64_t MutStart,
                                               size_t MaxSize) {
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  switch (Rand(4)) {
    case 3: return ChangeBinaryInteger<uint64_t>(Data, Size, MutStart, Rand);
    case 2: return ChangeBinaryInteger<uint32_t>(Data, Size, MutStart, Rand);
    case 1: return ChangeBinaryInteger<uint16_t>(Data, Size, MutStart, Rand);
    case 0: return ChangeBinaryInteger<uint8_t>(Data, Size, MutStart, Rand);
    default: assert(0);
  }
  return std::make_tuple(0, 0, 0);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate_CrossOver(uint8_t *Data,
                                     size_t Size,
                                     int64_t MutStart,
                                     size_t MaxSize) {
  std::tuple<size_t, size_t, size_t> MutInfo;
  if (Size > MaxSize) return std::make_tuple(0, 0, 0);
  if (!Corpus || Corpus->size() < 2 || Size == 0) return std::make_tuple(0, 0, 0);
  size_t Idx = Rand(Corpus->size());
  const Unit &O = (*Corpus)[Idx];
  if (O.empty()) return std::make_tuple(0, 0, 0);
  MutateInPlaceHere.resize(MaxSize);
  auto &U = MutateInPlaceHere;
  size_t NewSize = 0;
  switch(Rand(3)) {
    case 0:
      MutInfo = CrossOver(Data, Size, O.data(), O.size(), U.data(), U.size());
      NewSize = std::get<2>(MutInfo);
      break;
    case 1:
      MutInfo = InsertPartOf(O.data(), O.size(), U.data(), U.size(), MutStart, MaxSize);
      NewSize = std::get<2>(MutInfo);
      if (NewSize)
        break;
      // LLVM_FALLTHROUGH;
    case 2:
      MutInfo = CopyPartOf(O.data(), O.size(), U.data(), U.size(), MutStart);
      NewSize = std::get<2>(MutInfo);
      break;
    default: assert(0);
  }
  assert(NewSize > 0 && "CrossOver returned empty unit");
  assert(NewSize <= MaxSize && "CrossOver returned overisized unit");
  memcpy(Data, U.data(), NewSize);
  return std::make_tuple(std::get<0>(MutInfo),
                         std::get<1>(MutInfo),
                         std::get<2>(MutInfo));
}

void MutationDispatcher::StartMutationSequence() {
  CurrentMutatorSequence.clear();
  CurrentDictionaryEntrySequence.clear();
}

// Copy successful dictionary entries to PersistentAutoDictionary.
void MutationDispatcher::RecordSuccessfulMutationSequence() {
  for (auto DE : CurrentDictionaryEntrySequence) {
    // PersistentAutoDictionary.AddWithSuccessCountOne(DE);
    DE->IncSuccessCount();
    // Linear search is fine here as this happens seldom.
    if (!PersistentAutoDictionary.ContainsWord(DE->GetW()))
      PersistentAutoDictionary.push_back({DE->GetW(), 1});
  }
}

void MutationDispatcher::PrintRecommendedDictionary() {
  std::vector<DictionaryEntry> V;
  for (auto &DE : PersistentAutoDictionary)
    if (!ManualDictionary.ContainsWord(DE.GetW()))
      V.push_back(DE);
  if (V.empty()) return;
  Printf("###### Recommended dictionary. ######\n");
  for (auto &DE: V) {
    Printf("\"");
    PrintASCII(DE.GetW(), "\"");
    Printf(" # Uses: %zd\n", DE.GetUseCount());
  }
  Printf("###### End of recommended dictionary. ######\n");
}

void MutationDispatcher::PrintMutationSequence() {
  Printf("MS: %zd ", CurrentMutatorSequence.size());
  for (auto M : CurrentMutatorSequence)
    Printf("%s-", M.Name);
  if (!CurrentDictionaryEntrySequence.empty()) {
    Printf(" DE: ");
    for (auto DE : CurrentDictionaryEntrySequence) {
      Printf("\"");
      PrintASCII(DE->GetW(), "\"-");
    }
  }
}

void MutationDispatcher::PrintMutationDebug(int n) {
  if (n == 0)
    n = CurrentMutatorSequence.size();
  Printf("MSDEBUG:%zd:", n);
  for (int i = 0; i < n; i++)
    Printf("%s-", CurrentMutatorSequence[i].Name);
  Printf("\n");
}

void MutationDispatcher::PrintCurrentMutation(int n, std::string s) {
  if (CurrentMutatorSequence.size() > n)
    Printf("STEP:%s:%s\n", CurrentMutatorSequence[n].Name, s.c_str());
}

size_t MutationDispatcher::GetLastMutationIdx() {
  size_t idx = std::stoi(CurrentMutatorSequence[CurrentMutatorSequence.size() - 1].Name);
  return idx;
}

/* returns <MutationStart, MutationLength, NewSize> */
std::tuple<size_t, size_t, size_t>
MutationDispatcher::Mutate(uint8_t *Data, size_t Size, int64_t MutStart,
                           size_t MaxSize,
                          std::vector<std::pair<float, uint32_t> > *QTableEntry) {
  return MutateImpl(Data, Size, MutStart, MaxSize, MutatorScores, Mutators, QTableEntry);
}

std::tuple<size_t, size_t, size_t>
MutationDispatcher::DefaultMutate(uint8_t *Data, size_t Size, int64_t MutStart,
                                  size_t MaxSize,
                                  std::vector<std::pair<float, uint32_t> > *QTableEntry) {
  return MutateImpl(Data, Size, MutStart, MaxSize, MutatorScores, DefaultMutators, QTableEntry);
}

#if 0
// Create a copy of the vector together with the indexes and sort it
std::vector<std::pair<float, uint32_t> >
MutationDispatcher::SortVectorWithIdx(std::vector<float> v) {
  if (v.empty()) {
    return std::vector<std::pair<float, uint32_t> >();
  }

  std::vector<std::pair<float, uint32_t> > p;
  p.reserve(v.size());

  for (uint32_t i = 0 ; i != v.size() ; i++) {
      p.push_back(std::make_tuple(v[i], i));
  }
  std::sort(p.begin(), p.end(), std::greater<std::pair<float, uint32_t> >());
  return p;
}
#endif

void MutationDispatcher::setCConst(size_t d)
{
  /* feels like we need to amortize for the total time we will run */
  uint32_t norm = 10;
  CConst = (long double)(norm * d * d) / Mutators.size();
}

void MutationDispatcher::updateEpsilon(size_t d, size_t t)
{
  long double e = (long double)(CConst * Mutators.size()) / (d * d * t);
  Epsilon = (e < 1.0) ? e : 1.0;
}

template <typename T>
std::vector<size_t> sort_indexes(const std::vector<T> &v) {

  // initialize original index locations
  std::vector<size_t> idx(v.size());
  std::iota(idx.begin(), idx.end(), 0);

  // sort indexes based on comparing values in v
  std::sort(idx.begin(), idx.end(),
       [&v](size_t i1, size_t i2) {return v[i1] > v[i2];});

  return idx;
}

// Mutates Data in place, returns new size.
std::tuple<size_t, size_t, size_t>
MutationDispatcher::MutateImpl(uint8_t *Data, size_t Size,
                               int64_t MutStart,
                               size_t MaxSize,
                               std::vector<uint64_t> MutScores,
                               const std::vector<Mutator> &Mutators,
                               std::vector<std::pair<float, uint32_t> > *MutV) {
  assert(MaxSize > 0);
  if (Size == 0) {
    for (size_t i = 0; i < MaxSize; i++)
      Data[i] = RandCh(Rand);
    if (Options.OnlyASCII)
      ToASCII(Data, MaxSize, Options,
              ManualChrDictionary[TrueRand(ManualChrDictionary.size())].GetW().data()[0]);
    return std::make_tuple(0, MaxSize, MaxSize);
  }
  assert(Size > 0);

  Mutator M;

  std::mt19937_64 rng;
  int64_t timeSeed =
    std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::seed_seq ss{uint32_t(timeSeed & 0xffffffff), uint32_t(timeSeed>>32)};
  rng.seed(ss);
  std::uniform_real_distribution<long double> unif(0, 1);
  // std::vector<std::pair<float, uint32_t> > MutV;
  std::tuple<size_t, size_t, size_t> MutPair;

  // Some mutations may fail (e.g. can't insert more bytes if Size == MaxSize),
  // in which case they will return 0.
  // Try several times before returning un-mutated data.

  long double random = unif(rng);
  //Epsilon = unif(rng);
  Epsilon = 0.5;
  // std::sort(MutScores.begin(), MutScores.end(), std::greater<int>());

  for (int Iter = 0; Iter < 100; Iter++) {
    for (auto idx: sort_indexes(MutScores)) {
      // we don't update a bit if we just stick to the dictionary
      if (Options.OnlyDict && (idx == 4 || idx == 6 || idx == 7))
        continue;
      // DeathMode 1 & 3 affect the mutators
      if (Options.DeathMode % 2 == 1 && idx < Mutators.size() && random <= 1 - Epsilon) {
        M = Mutators[idx];
      } else {
        do {
          idx = TrueRand(Mutators.size());
        } while (Options.OnlyDict && (idx == 4 || idx == 6 || idx == 7));
        /* pick at random out of ALL */
        M = Mutators[idx];
      }

      random = unif(rng);
      if (Options.DeathMode > 2 && random <= 1 - Epsilon) {
        // with some probability, mutate within the bucket with the highest
        // score
        uint32_t bucketSize = Options.MaxLen / Options.ScoreBuckets;
        MutStart = (std::max_element(MutatorBucketScores.begin(),
                                     MutatorBucketScores.end()) - MutatorBucketScores.begin()) * bucketSize;
        MutStart += Rand(bucketSize);
      }

      MutPair = (this->*(M.Fn))(Data, Size, MutStart, MaxSize);
      if (std::get<2>(MutPair) && std::get<2>(MutPair) <= MaxSize) {
        if (Options.OnlyASCII)
          ToASCII(Data, std::get<2>(MutPair), Options,
              ManualChrDictionary[TrueRand(ManualChrDictionary.size())].GetW().data()[0]);
        CurrentMutatorSequence.push_back(M);
        return std::make_tuple(std::get<0>(MutPair),
                               std::get<1>(MutPair),
                               std::get<2>(MutPair));
      }
    }
  }

  return std::make_tuple(0, 0, std::min(Size, MaxSize));
}

void MutationDispatcher::AddWordToManualDictionary(const Word &W) {
  ManualDictionary.push_back(
      {W, std::numeric_limits<size_t>::max()});
}

void MutationDispatcher::AddWordToManualChrDictionary(const Word &W) {
  ManualChrDictionary.push_back(
      {W, std::numeric_limits<size_t>::max()});
}

void MutationDispatcher::AddWordToAutoDictionary(DictionaryEntry DE) {
  static const size_t kMaxAutoDictSize = 1 << 14;
  if (TempAutoDictionary.size() >= kMaxAutoDictSize) return;
  TempAutoDictionary.push_back(DE);
}

void MutationDispatcher::ClearAutoDictionary() {
  TempAutoDictionary.clear();
}

}  // namespace fuzzer
