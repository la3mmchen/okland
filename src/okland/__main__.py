#!/usr/bin/env python3

from .generics import *
from .kics import *
import fire

def main():
    """
    handle resulsts from static code analysis toolings. 
    
    most prominent create metrics and send results over to a prometheus pushgateway.

    """
    fire.Fire({
      'kics': Kics,
    })
  
if __name__ == '__main__':
    main()