#!/usr/bin/env python3
from .base import BaseRainbowTable
from .rainbow_table import RainbowTable
from .random_seed import RandomSeededRainbowTableMixin
from .printing import DemoPrintingMixin
from .bench import LookupBenchmarkMixin


class RandomSeededRainbowTable(RandomSeededRainbowTableMixin, RainbowTable):
    """
    A Rainbow Table implementation that combines random seeding with the base RainbowTable functionality.
    """
    pass
