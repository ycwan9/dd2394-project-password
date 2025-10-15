#!/usr/bin/env python3
import random


class RandomSeededRainbowTableMixin():
    """
    A mixin class to add functionality for building a rainbow table
    using randomly generated seeds. This class is intended to be used
    in conjunction with a class inheriting from BaseRainbowTable that
    provides the reduction function.
    """

    def build_random_table(self, num_seeds: int):
        """
        Builds the rainbow table using a specified number of randomly generated seeds.

        Args:
            num_seeds: The number of random seeds to generate.
        """
        def generate_seeds(n: int):
            """Generator function to yield random binary seeds."""
            for _ in range(n):
                # Generate random binary data as seeds. The size of the binary data
                # can be adjusted based on the expected input size of the hash function
                # or reduction function if it has specific size constraints.
                random_seed = random.getrandbits(256).to_bytes(32, 'big') # Generate 32 random bytes
                yield random_seed

        self.build_table(generate_seeds(num_seeds))
