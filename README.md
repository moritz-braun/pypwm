# pypwm
##In this project a fully functional and secure password manager is implemented in python.  Both a command line as well as a gui version are provided.

The password manager works as follows:
1. passwordinfo is saved in a dictionary, i.e password=p[service]
2. This dictionary  is pickled to a string.
3. This string  is encrypted and saved to the hard drive with AES.
4. Encryption key is obtained from the lowest 16 bytes of SHA256(masterpassword)
5. masterpassword is hashed with SHA512
6. On request a random password  is generated and saved
7. The user can change the masterpassword without losing the password information
8. On request the password is coped to the clip board to copy  password with the mouse into the application.
