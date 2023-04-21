import socket
import sys
import struct

class Slave:
   GID = ""
   RID = ""
   NEXTSLAVEIP = ""


   def main():
      #Get value from argv
      if(len(sys.argv) != 3) :
         raise Exception("Parameter(s): <Slave> <MasterHostName> <MasterPort#>")
      host = sys.argv[1]
      port = int(sys.argv[2])

      #Create socket
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
      print "Welcome!\n"
      print "Trying to connect:"
      print "MasterHostName: %s, MasterPort#: %s" %(host, port)

      #Connect to Master
      s.connect((host, port))
      host_ip = socket.gethostbyname(host)
      print "Master ip: %s\n" %host_ip
      print "Connected to Master...Creating packet\n"

      #Set values for packet
      gid = (port - 10010) / 5
      key = 0x4A6F7921
      buf = bytearray([gid & 0xFF, key >>24 & 0xFF, key >> 16 & 0xFF, key >> 8 & 0xFF, key & 0xFF])
      print "Data:",
      for element in buf:
         print "%s" %element,
      print "GID: %s" %buf[0]
      key = buf[1] << 24 | buf[2] << 16 | buf[3] << 8 | buf[4]
      print "MAGIC NUMBER: ", hex(key)
      
      #buf = bytearray([key >>24 & 0xFF, key >> 16 & 0xFF, key >> 8 & 0xFF, key & 0xFF])             - uncomment this line for testing error scenario: sending packet not containing 5 bytes
      #buf = bytearray([gid & 0xFE, key >>24 & 0xFF, key >> 16 & 0xFF, key >> 8 & 0xFF, key & 0xFF]) - uncomment this line for testing error scenario: sending invalid GID
      #buf = bytearray([gid & 0xFF, key >>24 & 0x0F, key >> 16 & 0xFF, key >> 8 & 0xFF, key & 0xFF]) - uncomment this line for testing error scenario: sending invalid key
      
      #Sending packet
      print "\nSending request to Master...\n"
      s.send(buf)
      print "Request is sent to Master...Listening reply\n"

      #Receiving packet
      data = s.recv(10)
      #Check validity of the packet
      if struct.unpack('>H',b'\x00' + data[0])[0] & 0x80 == 0x80:
         print "Invalid packet was sent\n"
         return
      print "Received", repr(data)

      #Get values from packet
      gid = struct.unpack('>H',b'\x00' + data[0])[0]
      magic = ord(data[1]) << 24 | ord(data[2]) << 16 | ord(data[3]) << 8 | ord(data[4])
      rid = struct.unpack('>H',b'\x00' + data[5])[0]
      nextIP = ord(data[6]) << 24 | ord(data[7]) << 16 | ord(data[8]) << 8 | ord(data[9])
      IP32Bit = struct.pack('!I', nextIP)
      GID = gid
      RID = rid
      NEXTSLAVEIP = socket.inet_ntoa(struct.pack('>L',nextIP))
      s.close

      #Result 
      print "GID: ", GID
      print "KEY: ", hex(magic)
      print "RID: ", RID
      print "Next Slave IP: ", NEXTSLAVEIP
      print "\n"
      print "Slave status:"
      print "GID: ", GID
      print "RID: ", RID
      print "NEXTSLAVEIP: ", NEXTSLAVEIP
      print "\nNow you joined the ring!!\n"
   if __name__ == '__main__':
      main()
