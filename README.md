# Windentifier

Windentifier is a tool for retrieving various Windows identifiers and IDs. It can fetch identifiers such as the Windows Product ID, Motherboard Serial Number, Physical MAC Address, Volume Serial Numbers, and Machine GUID. This tool can be useful in various scenarios, such as for an anti-cheat system to ban hardware IDs (HWIDs).




## Features

- Retrieve Windows Product ID
- Retrieve Motherboard Serial Number
- Retrieve Physical MAC Address
- Retrieve Volume Serial Numbers
- Retrieve Machine GUID
- Retrieve The Routers Mac Address
- Retrieve Windows Username
- Retrieve SystemUUID
- Retrieve CPUID
- Retrieve hexadecimal representation of the binary data stored in the EkPub(the only thing admin rights are needed for)


## Installation

To install this project, you can clone the repository using the following command:

##### Clone it
```bash
git clone https://github.com/maxiwee69/Windentifier
```
##### CD into it
```bash
cd Windentifier
```
##### Compile it
```bash
nmake 
```
##### Or 
```bash
cl /O1 /MD /EHsc main.cpp Ole32.lib wbemuuid.lib Advapi32.lib Slc.lib /link /OPT:REF /OPT:ICF /OUT:windentifier.exe 
```



## Optimizations

None, this is a base for people to get started with this so ill leave all of this up to you guys <3


## Authors

- [@maxiwee69](https://github.com/maxiwee69)
- [Github Copilot](https://github.com/features/copilot)


## Acknowledgements

 - [Readme.so](https://readme.so/editor)
 - [Github Copilot](https://github.com/features/copilot)
 - [Some random StackOverflow thread](https://stackoverflow.com/questions/910619/generating-a-hardware-id-on-windows)
## Contributing

Contributions are always welcome!



## License

[MIT](https://choosealicense.com/licenses/mit/)


## FAQ

### How secure is this?

Idk man, if you mean if its malware or some shit, read the code or just trust me on this one

### Is this easily bypassible

I think so, havent tried
