# SlowFuzz

A spin on libFuzzer so as to favor inputs incurring a slowdown. The key
modifications consist of changing the fitness function, to favor inputs that
excercise more basic block edges, as well as introducing probabilities in the
selection of mutations to be performed, so as to preserve "locality" of the
created inputs.

In particular, there are 4 available modes for mutations:

* Random: the mutation is selected at random.
    
* Mutation priority: Prioritize mutations that were successful in previous runs
    
* Offset priority: Prioritize mutating certain offsets (`buckets` of the
    input). The number of buckets to split the input into is controlled via
    the `score_buckets` parameter.
    
* Hybrid mode: Keep a score for the different mutations for each input
    bucket

The respective mutation mode to be used is controlled via the `-death_mode`
option (run the compiled binary with `-help=1` for all available options)

Finally, this implementation adds some functionality with respect to using
dictionary files. In particular, the options `-only_dict=1` limits libfuzzer
to only use characters provided in the given dictionary (one character per line)
and to not introduce any other characters.

For more information see the [SlowFuzz paper](https://arxiv.org/pdf/1708.08437.pdf).


# Example usage

To see how SlowFuzz generates inputs causing a slowdown for a given
implementation, let's pick a simple example of an insertion sort
implementation. To this end, run:

```
cd apps/isort
make fuzzer
make
make test
```

A directory `out/` is created, containing all the units that caused a slowdown.
