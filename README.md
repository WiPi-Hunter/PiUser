
```python

             ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
            ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
            ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
            ▐░▌       ▐░▌             ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌       ▐░▌
            ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
            ▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
            ▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌       ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀ 
            ▐░▌               ▐░▌     ▐░▌       ▐░▌          ▐░▌▐░▌          ▐░▌     ▐░▌  
            ▐░▌           ▄▄▄▄█░█▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌ 
            ▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
             ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀ 


                        Analyze user behavior against fake access points               

```

#### Purpose

📡 Examine probe requests in the environment to determine if they have previously connected to the malicious network
📡 Thus, the number of people who are likely to fall into the potentially fake access point in the environment is determined

<p align="center">
<img src="https://github.com/WiPi-Hunter/PiUser/blob/master/images/piuser_pro.png" height="%50" width="60%">
</p>

For corporation environment

+ Monitors company name in probe requests
+ Monitors blacklist ssids in probe requests

For clients

+ Analyzes behavior the clients of the corporation with probe requests

**Screenshots:**
<p align="center">
<img src="https://github.com/WiPi-Hunter/PiUser/blob/master/images/piuser2.png" height="%50" width="60%">
</p>


#### DEMO

+ https://www.youtube.com/watch?v=CYt1JnEZfcU

----

### Usage (for Linux)

#### Requirements

* **Modules:** time, termcolor, commands, interfaces, os
* **OS:** Kali, Ubuntu
* **Python Version:** 2.x

Download PiUser:

`git clone https://github.com/WiPi-Hunter/PiUser.git`

Install Python librarie(s):

`pip install -r requirements.txt`

It's done!

Run the program with following command: 

Run:

```python
cd PiUser
python piuser.py
```
