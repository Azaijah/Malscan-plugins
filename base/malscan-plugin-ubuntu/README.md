# malscan-plugin-ubuntu
*  Base image for malscan plugins that cannot use alpine
*  ubuntu trusty release with tini
*  Included in image:
   *  /malware folder to mount malware from source disk 
   *  malscan user and group
   *  EICAR test file  
* NOTE:
Must add must prefix:
 ["/usr/local/bin/tini]
 To applications using ubuntu as the base image 
    * Example:
      Change this:
      ENTRYPOINT ["/docker-entrypoint.sh"]
      To this:
      ENTRYPOINT ["/usr/local/bin/tini", "--", "/docker-entrypoint.sh"]