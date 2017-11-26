//===- FuzzerMutate.h - Internal header for the Fuzzer ----------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::MutationDispatcher
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_MUTATE_H
#define LLVM_FUZZER_MUTATE_H

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerRandom.h"

namespace fuzzer {

class MutationDispatcher {
public:
  MutationDispatcher(Random &Rand, Random &TrueRand,
                     const FuzzingOptions &Options);
  ~MutationDispatcher() {}
  /// Indicate that we are about to start a new sequence of mutations.
  void StartMutationSequence();
  /// Print the current sequence of mutations.
  void PrintMutationSequence();
  void PrintMutationDebug(int n);
  void PrintCurrentMutation(int n, std::string s);
  size_t GetLastMutationIdx();
  /// Indicate that the current sequence of mutations was successfull.
  void RecordSuccessfulMutationSequence();
  /// Mutates data by invoking user-provided mutator.
  size_t  Mutate_Custom(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by invoking user-provided crossover.
  size_t  Mutate_CustomCrossOver(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by shuffling bytes.
  std::tuple<size_t, size_t, size_t>  Mutate_ShuffleBytes(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by erasing bytes.
  std::tuple<size_t, size_t, size_t>  Mutate_EraseBytes(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by inserting a byte.
  std::tuple<size_t, size_t, size_t>  Mutate_InsertByte(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by inserting several repeated bytes.
  std::tuple<size_t, size_t, size_t>  Mutate_InsertRepeatedBytes(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by chanding one byte.
  std::tuple<size_t, size_t, size_t>  Mutate_ChangeByte(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by chanding one bit.
  std::tuple<size_t, size_t, size_t>  Mutate_ChangeBit(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Mutates data by copying/inserting a part of data into a different place.
  std::tuple<size_t, size_t, size_t>  Mutate_CopyPart(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);

  /// Mutates data by adding a word from the manual dictionary.
  std::tuple<size_t, size_t, size_t>  Mutate_AddWordFromManualDictionary(uint8_t *Data, size_t Size, int64_t MutStart,
                                            size_t MaxSize);

  /// Mutates data by adding a word from the temporary automatic dictionary.
  std::tuple<size_t, size_t, size_t>  Mutate_AddWordFromTemporaryAutoDictionary(uint8_t *Data, size_t Size, int64_t MutStart,
                                                   size_t MaxSize);

  /// Mutates data by adding a word from the persistent automatic dictionary.
  std::tuple<size_t, size_t, size_t>  Mutate_AddWordFromPersistentAutoDictionary(uint8_t *Data, size_t Size, int64_t MutStart,
                                                    size_t MaxSize);

  /// Tries to find an ASCII integer in Data, changes it to another ASCII int.
  std::tuple<size_t, size_t, size_t>  Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);
  /// Change a 1-, 2-, 4-, or 8-byte integer in interesting ways.
  std::tuple<size_t, size_t, size_t>  Mutate_ChangeBinaryInteger(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);

  /// CrossOver Data with some other element of the corpus.
  std::tuple<size_t, size_t, size_t>  Mutate_CrossOver(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize);

  /// Applies one of the configured mutations.
  /// Returns the new size of data which could be up to MaxSize.
  std::tuple<size_t, size_t, size_t>  Mutate(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize,
                      std::vector<std::pair<float, uint32_t> > *QTableEntry);
  /// Applies one of the default mutations. Provided as a service
  /// to mutation authors.
  std::tuple<size_t, size_t, size_t>
    DefaultMutate(uint8_t *Data, size_t Size, int64_t MutStart, size_t MaxSize,
                  std::vector<std::pair<float, uint32_t> > *QTableEntry);

  /// Creates a cross-over of two pieces of Data, returns its size.
  std::tuple<size_t, size_t, size_t>
    CrossOver(const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
              size_t Size2, uint8_t *Out, size_t MaxOutSize);

  std::vector<std::pair<float, uint32_t> > SortVectorWithIdx(std::vector<float> v);
  void updateEpsilon(size_t d, size_t t);
  void setCConst(size_t d);

  int GetMutatorsSize();
  void IncreaseMutatorScore(uint32_t idx);
  void IncreaseMutatorBucketScore(uint32_t idx);
  std::vector<uint64_t> GetMutatorBuckets();
  uint64_t GetMutatorScore(uint32_t idx);
  void AddWordToManualDictionary(const Word &W);
  void AddWordToManualChrDictionary(const Word &W);

  void AddWordToAutoDictionary(DictionaryEntry DE);
  void ClearAutoDictionary();
  void PrintRecommendedDictionary();

  void SetCorpus(const InputCorpus *Corpus) { this->Corpus = Corpus; }

  Random &GetRand() { return Rand; }

  long double Epsilon = 1.0;

private:

  struct Mutator {
    std::tuple<size_t, size_t, size_t>
    (MutationDispatcher::*Fn)(uint8_t *Data, size_t Size, int64_t MutStart, size_t Max);
    const char *Name;
  };

  std::tuple<size_t, size_t, size_t>
    AddWordFromDictionary(Dictionary &D, uint8_t *Data, size_t Size, int64_t MutStart,
                          size_t MaxSize);
  std::tuple<size_t, size_t, size_t>
    MutateImpl(uint8_t *Data,
               size_t Size,
               int64_t MutStart,
               size_t MaxSize,
               std::vector<uint64_t> MutScores,
               const std::vector<Mutator> &Mutators,
               std::vector<std::pair<float, uint32_t> > *QTableEntry);
  std::tuple<size_t, size_t, size_t>
    InsertPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                 size_t ToSize, int64_t MutStart, size_t MaxToSize);
  std::tuple<size_t, size_t, size_t>
    CopyPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                    size_t ToSize, int64_t MutStart);

  Random &Rand;
  Random &TrueRand;
  const FuzzingOptions &Options;

  // Dictionary provided by the user via -dict=DICT_FILE.
  Dictionary ManualDictionary;
  // Dictionary holding characters in -dict=DICT_FILE
  Dictionary ManualChrDictionary;
  // Temporary dictionary modified by the fuzzer itself,
  // recreated periodically.
  Dictionary TempAutoDictionary;
  // Persistent dictionary modified by the fuzzer, consists of
  // entries that led to successfull discoveries in the past mutations.
  Dictionary PersistentAutoDictionary;
  std::vector<Mutator> CurrentMutatorSequence;
  std::vector<DictionaryEntry *> CurrentDictionaryEntrySequence;
  const InputCorpus *Corpus = nullptr;
  std::vector<uint8_t> MutateInPlaceHere;

  std::vector<Mutator> Mutators;
  std::vector<uint64_t> MutatorScores;
  std::vector<uint64_t> MutatorBucketScores;
  std::vector<Mutator> DefaultMutators;

  std::vector<int32_t> Deltas;
  long double CConst = 0.0;
  size_t SwitchGen = 100000;
};

}  // namespace fuzzer

#endif  // LLVM_FUZZER_MUTATE_H
