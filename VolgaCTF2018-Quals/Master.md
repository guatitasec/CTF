# Master

**Category:** Forensics

**Description:** 

```
We've found one of C&C servers that controlled recent DDoS attack, however we can't get credentials.

http://master.quals.2018.volgactf.ru:3333

Also, we've got a communication traffic dump between C&C servers.

capture.pcap

Can you get in?
```

**Solution:** 

The Command and Control server found at: http://master.quals.2018.volgactf.ru:3333 displayed a login form. As per the description of the challenge, the task was to obtain credentials to login to this site.

![VolgaCTF2018-Quals-Master](https://github.com/guatitasec/CTF/blob/master/VolgaCTF2018-Quals/images/volgactf2018-master-1.png)

We started by analyzing the pcap. On first inspection, We saw a lot of malformed packets which may be related to the DDoS attack. However, there was also some MySQL communication which may be of importance.

![VolgaCTF2018-Quals-Master](https://github.com/guatitasec/CTF/blob/master/VolgaCTF2018-Quals/images/volgactf2018-master-2.png)

We applied a filter to display only MySQL packets, and further analyzed them. The packets contained queries to a **users** table, with usernames and what looked like passwords.

![VolgaCTF2018-Quals-Master](https://github.com/guatitasec/CTF/blob/master/VolgaCTF2018-Quals/images/volgactf2018-master-3.png)

We were initially skeptical that passwords would be stored in plaintext. However, we went ahead and tried some of them out in the login form. To our surprise, we were logged in, with a message that said: "No flag for you!". What this tells us is that there may be an user for whom there is a flag.

Our first intuition was that this user may be "admin", so we went ahead and applied a filter to only show packets that contained the word "admin". Effectively, we got a username and password.

![VolgaCTF2018-Quals-Master](https://github.com/guatitasec/CTF/blob/master/VolgaCTF2018-Quals/images/volgactf2018-master-4.png)

We tried the credentials, and obtained the flag:

![VolgaCTF2018-Quals-Master](https://github.com/guatitasec/CTF/blob/master/VolgaCTF2018-Quals/images/volgactf2018-master-5.png)
