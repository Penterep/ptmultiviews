[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


# PTMULTIVIEWS
> Apache Multiviews detection & enumeration tool

ptmultiviews is a tool that allows for detection and exploitation of Apache Multiviews. <br/>
ptmultiviews can exploit Apache Multiviews by enumerating all alternatives for requested resource - this leads to an easy revelation of files that would be otherwise hard to find, such as backup files.


## Installation
```
pip install ptmultiviews
```

## Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.

> Add to PATH for Bash
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

> Add to PATH for ZSH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshhrc
source ~/.zshhrc
```

## Usage examples

```
ptmultiviews -u https://www.example.com/                          # Test single URL for MultiViews vulnerability and retrieve alternatives
ptmultiviews -u https://www.example.com/ -co                      # Test single URL for MultiViews vulnerability without enumeration
ptmultiviews -u https://www.example.com/index.php -o output.txt   # Saves enumerated files to output.txt
ptmultiviews -f urlList.txt                                       # Enumerate all files from urlList
```


### Options:

```
-u   --url                 <url>           Connect to URL
-f   --file                <file>          Load list of URLs from file
-d   --domain              <domain>        Domain to test (use with <file> argument)
-co  --check-only                          Check for multiviews without enumerating
-wr  --with-requested-url                  Includes requested source among enumerated results
-wd  --without-domain                      Enumerated files will be printed without domain
-t   --threads             <threads>       Set number of threads (default 20)
-p   --proxy               <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
-T   --timeout             <timeout>       Set timeout (default 10)
-c   --cookie              <cookie>        Set cookie
-ua  --user-agent          <ua>            Set User-Agent header
-H   --headers             <header:value>  Set custom header(s)
-o   --output              <output>        Save output to file
-r   --redirects                           Follow redirects (default False)
-C   --cache                               Cache HTTP communication (load from tmp in future)
-v   --version                             Show script version and exit
-h   --help                                Show this help message and exit
-j   --json                                Output in JSON format
```

## Dependencies

```
requests
validators
ptlibs
```

## Version History
```
1.0.0
    - Code improvements
    - Updated for ptlibs 1.0.0
0.0.1 - 0.0.3
    - Alpha releases
```

## License

Copyright (c) 2023 Penterep Security s.r.o.

ptmultiviews is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptmultiviews is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptmultiviews. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
