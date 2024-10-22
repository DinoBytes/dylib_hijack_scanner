# Dylib Hijack Scanner

Simple utility used to scan a directory for possibly dylib hijacks.

## Usage

```
$ pip install -r requirements.txt
$ python scan.py
Usage: python scan.py <directory>
```

Example usage:
```
$ python scan.py "/Library/Application Support/"
```

Output is simply a pretty print of a dict containing the vulnerable file and the libraries that *may* be susceptible to hijacking.

## False Positives

This tool makes no guarantees in terms of accuracy of results. It makes no attempt to check permissions or other such mitigations of the vulnerabilities.


## Acknowledgements

While this tool was created for use in a couple of independent projects, it was inspired by [Patrick Wardle's](https://objective-see.com/blog.html) scanner of the same nature -- [DHS.app](https://objective-see.com/products/dhs.html). His tooling is much more sophisticated and thorough, but didn't meet my use case. 
