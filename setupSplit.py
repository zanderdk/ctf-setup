#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals

import sys
from os import path


directory, file = path.split(__file__)
directory       = path.expanduser(directory)
directory       = path.abspath(directory)

sys.path.append(directory)

import splitmind # isort:skip
(splitmind.Mind()
  .right(of="main", display="regs", size="80")
  .below(of="regs", display="stack", size="20")
  .below(of="stack", display="backtrace", size="8")
).build()

