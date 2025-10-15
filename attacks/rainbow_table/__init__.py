#!/usr/bin/env python3
from .base import BaseRainbowTable
from .rainbow_table import RainbowTable
from .random_seed import RandomSeededRainbowTableMixin


class RandomSeededRainbowTable(RandomSeededRainbowTableMixin, RainbowTable):
    """
    A Rainbow Table implementation that combines random seeding with the base RainbowTable functionality.
    """
    pass
