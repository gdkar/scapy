import os,sys,socket,types
import random,time
import gzip,zlib,cPickle
import re,struct,array
import subprocess
import subprocess

import warnings
warnings.filterwarnings("ignore","tempnam",RuntimeWarning, __name__)

from itertools import takewhile, islice
from config import conf
from data import MTU
from error import log_runtime, log_loading, log_interactive, Scapy_Exception
from base_classes import BasePacketList

@conf.commands.register
def rdpcap(filename, count=-1):
    """Read a pcap file and return a packet list
count: read only <count> packets"""
    return PcapReader(filename).read_all(count=count)



class RawPcapReader:
    """A stateful pcap reader. Each packet is returned as a string"""

    def __init__(self, filename):
        self.filename = filename
        try:
            self.f = gzip.open(filename,"rb")
            magic = self.f.read(4)
        except IOError:
            self.f = open(filename,"rb")
            magic = self.f.read(4)
        if magic == "\xa1\xb2\xc3\xd4": #big endian
            self.endian = ">"
        elif  magic == "\xd4\xc3\xb2\xa1": #little endian
            self.endian = "<"
        else:
            raise Scapy_Exception("Not a pcap capture file (bad magic)")
        hdr = self.f.read(20)
        if len(hdr)<20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(self.endian+"HHIIII",hdr)

        self.linktype = linktype

    def __iter__(self):
        return self

    def __next__(self):
        """impliment the iterator protocol on a set of packets in a pcap file"""
        pkt = self.read_packet()
        if pkt == None:
            raise StopIteration
        return pkt

    def read_packet(self, size=MTU):
        """return a single packet read from the file
        
        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec,usec,caplen,wirelen = struct.unpack(self.endian+"IIII", hdr)
        s = self.f.read(caplen)[:MTU]
        return s,(sec,usec,wirelen) # caplen = len(s)

    def dispatch(self, callback):
        """call the specified callback routine for each packet read
        
        This is just a convienience function for the main loop
        that allows for easy launching of packet processing in a 
        thread.
        """
        for p in self:
            callback(p)

    def read_all(self,count=-1):
        """return a list of all packets in the pcap file
        """
        if count > 0:
            return list(islice(self,count,None,None))
        else:
            return list(self)

    def recv(self, size=MTU):
        """ Emulate a socket
        """
        return self.read_packet(size)[0]

    def fileno(self):
        return self.f.fileno()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.close()


class SeekablePcapReader(RawPcapReader):
    def __init__(self,filename):
        RawPcapReader.__init__(self,filename)
        self.toc = []
        for pkt in self:
            del pkt
        if self.toc:
            self.f.seek(self.toc[0])
    def read_packet(self,size=MTU):
        self.toc.append(self.f.tell())
        return RawPcapReader.read_packet(size)

    def read_packet_num(self, num):
        oldtell = self.f.tell()
        ret = None
        try:
            self.f.seek(self.toc[num])
            ret = self.read_packet()
        finally:
            self.f.seek(oldtell)
        return ret
class PcapReader(RawPcapReader):
    def __init__(self, filename):
        RawPcapReader.__init__(self, filename)
        try:
            self.LLcls = conf.l2types[self.linktype]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype,self.linktype))
            self.LLcls = conf.raw_layer
    def read_packet(self, size=MTU):
        rp = RawPcapReader.read_packet(self,size)
        if rp is None:
            return None
        s,(sec,usec,wirelen) = rp
        
        try:
            p = self.LLcls(s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = sec+0.000001*usec
        return p
    def read_all(self,count=-1):
        res = RawPcapReader.read_all(self, count)
        import plist
        return plist.PacketList(res,name = os.path.basename(self.filename))
    def recv(self, size=MTU):
        return self.read_packet(size)
        


class RawPcapWriter:
    """A stream PCAP writer with more control than wrpcap()"""
    def __init__(self, filename, linktype=None, gz=False, endianness="", append=False, sync=False):
        """
        linktype: force linktype to a given value. If None, linktype is taken
                  from the first writter packet
        gz: compress the capture on the fly
        endianness: force an endianness (little:"<", big:">"). Default is native
        append: append packets to the capture file instead of truncating it
        sync: do not bufferize writes to the capture file
        """
        
        self.linktype = linktype
        self.header_present = 0
        self.append=append
        self.gz = gz
        self.endian = endianness
        self.filename=filename
        self.sync=sync
        bufsz=4096
        if sync:
            bufsz=0

        self.f = [open,gzip.open][gz](filename,append and "ab" or "wb", gz and 9 or bufsz)
        
    def fileno(self):
        return self.f.fileno()

    def _write_header(self, pkt):
        self.header_present=1

        if self.append:
            # Even if prone to race conditions, this seems to be
            # safest way to tell whether the header is already present
            # because we have to handle compressed streams that
            # are not as flexible as basic files
            g = [open,gzip.open][self.gz](self.filename,"rb")
            if g.read(16):
                return
            
        self.f.write(struct.pack(self.endian+"IHHIIII", 0xa1b2c3d4L,
                                 2, 4, 0, 0, MTU, self.linktype))
        self.f.flush()
    

    def write(self, pkt):
        """accepts either a single packet or a list of packets to be
        written to the dumpfile

        """
        if type(pkt) is str:
            if not self.header_present:
                self._write_header(pkt)
            self._write_packet(pkt)
        else:
            pkt = pkt.__iter__()
            if not self.header_present:
                try:
                    p = pkt.next()
                except StopIteration:
                    self._write_header("")
                    return
                self._write_header(p)
                self._write_packet(p)
            for p in pkt:
                self._write_packet(p)

    def _write_packet(self, packet, sec=None, usec=None, caplen=None, wirelen=None):
        """writes a single packet to the pcap file
        """
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t=time.time()
            it = int(t)
            if sec is None:
                sec = it
            if usec is None:
                usec = int(round((t-it)*1000000))
        self.f.write(struct.pack(self.endian+"IIII", sec, usec, caplen, wirelen))
        self.f.write(packet)
        if self.gz and self.sync:
            self.f.flush()

    def flush(self):
        return self.f.flush()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, tracback):
        self.flush()
        self.close()


class PcapWriter(RawPcapWriter):
    def _write_header(self, pkt):
        if self.linktype == None:
            try:
                self.linktype = conf.l2types[pkt.__class__]
            except KeyError:
                warning("PcapWriter: unknown LL type for %s. Using type 1 (Ethernet)" % pkt.__class__.__name__)
                self.linktype = 1
        RawPcapWriter._write_header(self, pkt)

    def _write_packet(self, packet):
        sec = int(packet.time)
        usec = int(round((packet.time-sec)*1000000))
        s = str(packet)
        caplen = len(s)
        RawPcapWriter._write_packet(self, s, sec, usec, caplen, caplen)


