# Hscan

        ______  __                           
        ___  / / /__________________ _______ 
        __  /_/ /__  ___/  ___/  __ `/_  __ \
        _  __  / _(__  )/ /__ / /_/ /_  / / /
        /_/ /_/  /____/ \___/ \__,_/ /_/ /_/
                    By Anas LAABAB   

Is a BurpSuite extension which will help pentesters automatically detect CORS and JWT misconfigurations through many test cases. This was created to avoid the hurdle of manual testing while there are in-depth areas where time should be put on. Currently, It only supports the stated before misconfigurations, but code & new checks will be pushed as soon something feasible show up on the way.

# Installation

1. Install pyjwt library `python3 -m pip install pyjwt`
2. Download Jython. Go to `Extender > Options`, under Python Environment load the Jython standalone file
3. Under the same location, Set python installed libraries's location
4. Set up your configuration within the `config.py` file
5. Go to `Extender > Extensions`, then click Add and select `Hscan.py`

# Screenshots

![scsdc](/screenshots/screenshot.png)

# References

* https://www.bedefended.com/papers/cors-security-guide
* https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a
