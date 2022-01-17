# WMI_OS_information
Program connects to the WMI on the remote host and requests information about operating system and security center settings.

Requested information:

  From Root/Cimv2 namespace:
  
    - Operating system's name;    
    - Amount of available physical memory;    
    - Amount of available virtual memory;
    - Manufacturer of the OS;
    - Language of the system;
    - System Directory location;
    - Name of the registered user;
    - Number of registered users;
    - Version of the operating system;

    - List of installed programs and applications;

  From Roor/SecurityCenter2 namespace:
  
    - List of antiviruses facilities;

    - List of firewals facilities;

    - List of antispyware facilities;
