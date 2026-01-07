### Install
```
pip install -r requirements.txt
```

### Usage
The Script reads a list of provided selectors from a text file named <domain>.selectors.lst if existing at "./dkim" .
append them to a list of all selectors => provided + default = cleaned(used selectors)
the default selectors are stored in a file named "selectors.lst" which sits in the same folder (./dkim).
```
python test_dns.py dkim <domain>
```

example:
```
python test_dns.py dkim example.com
```
