import re, telnetlib, os
#version 0.1.2
#TODO: 
# log testing 
# config testing 
# auth encap in class, from config
class TelnetWorker:
    regexhash={
    'cisco':{
            'prompt':re.compile("\n([\w\d\-\.\(\)]+[>#%])"),
            'login':re.compile("(?:[Uu]sername:)"),
            'password':re.compile("[Pp]assword:"),
            'login_fail':re.compile('% Authentication failed'),
            'more':re.compile("( --[Mm]ore-- )"),
            'yesno':re.compile("\([Yy]/[Nn]\)\[[YyNn]\]",re.IGNORECASE),
            'more_key':' ',
            'more_replace':re.compile("\x08{1,25}\ *"),
            'extension':re.compile("(\{.+\}:)")
            },
    #s2300, s5600, s5300
    'huawei':{
            'prompt':re.compile("\n([<\[][\w\d\-\.\(\)\/]+[>\]#%])"),
            'login':re.compile("(?:[Uu]sername:)"),
            'password':re.compile("[Pp]assword:"),
            'login_fail':re.compile("((?:%|(?:Error:)) ?(?:(?:Login failed)|(?:The.*is invalid)|(?:Tacacs server reject)|(?:Wrong password)))"),
            'more':re.compile("([- ]+[Mm]ore ----)"),
            'yesno':re.compile("[\[\(][Yy][es]{0,2}/[Nn]o*[\]\)]",re.IGNORECASE),
            'more_key':' ',
            #        'more_replace':re.compile("/\x1b\x5b\d+D.*\x1b\x5b\d+D/"),
            'more_replace':re.compile("^.*\x1b\[[0-9]*D"),
            'extension':re.compile("(\{.+\}:)")
        },
    'dlink':{ #DES 1210 #DGS3420
# show ports and another commands with cycled "Next" works INCORRECT!!!
# deprecated  commands:  'show ports [\d:]*' 'show error ports [\d:]*' 'show ports description [\d:]*'
            # dialog starts with: ESC[0mESC[1;1HESC[2J
            'prompt':re.compile("([\x0d\x0a][\w\d\-]+:[\w\d]+#)"),
            # DES 1210: "DES-1210-28/ME login:"
            # DGS 3420: "UserName:"
            'login':re.compile("(?:[\x0d\x0a]UserName:)|(?:DES-1210-28/ME login:)"),
            'password':re.compile("[Pp]ass[Ww]ord:"),
            # DES 1210: % Incorrect Login/Password
            # DGS 3420: Fail! (V1_70)
            'login_fail':re.compile("(?:\x0dFail!)|(?:Bad Password!!!)|(?:% Incorrect Login/Password)"),
            'more':re.compile("([\x0d\x0a]\x1b.*\x1b.*A[Ll]{2}[^\x0a]*)"),
            'yesno':re.compile("\([Yy]/[Nn]\)",re.IGNORECASE), 
            'more_key':'n',
            'more_replace':re.compile("(^ *\x0d.*\x0d\x1b\[1A[^\x0d]*)|(\x1b\x0d *\x0d\x1b\[K)|(\x1b\[27m\x0d *\x0d*)"),
            'extension':re.compile("(\{.+\}:)")
            },

    }
    AUTH_OK=0
    TIMEOUT=-1
    AUTH_REJECT=10
    AUTH_NEED_LOGIN=20
    COMMAND_OK=0
    COMMAND_FAIL=1
    COMMAND_UNKNOWN=2
    def __init__(self, host, typ, timeout=5):
        self.conf={'debug':0,'logdir':'.','port':23}
        try :
            conf=open('telnetworker.conf')
            for line in conf.readlines():
                if line[0]!='#':
                    l=line.split('=')
                    self.conf[l[0]]=eval(l[1])
        except Exception, e:
#            print "can't open config file, use default settings."
            zero=0
        self.debug=self.conf['debug']
        #self.logname=os.path(self.conf['logdir'],host) #+'_'+time.now()+'.log')
        if self.debug:
            try: 
                self.logfile=open(self.logname,'w')
            except Exception, e:
                self.debug=0
                print ('Warning! can\'t open logfile: %s'%self.logname)
        self.host=host
        self.type=typ
        self.timeout=timeout
        self.regarray=self.regexhash[typ]
        self.prompt=None
        self.password=''
        self.logbuffer=[]
        self.outbuffer=[]
        self.tn=telnetlib.Telnet()
        self.reconnect()
        
    def reconnect(self):
        if self.tn.sock!=None and self.tn.sock!=0:
            if self.debug &2 :
                self.logbuffer.append('DEBUG: closing connection')
            self.tn.close()
        self.tn.open(self.host,self.conf['port'])
        if self.debug &2 :
            self.logbuffer.append('DEBUG: open connection to %s'%self.host)

    def setType(self,typ):
        self.type=typ
        self.regarray=self.regexhash[typ]

    def authenticate(self):
        user1,pass1=self.authdata[0]
        res=self.auth(login=user1,password=pass1)
        if res==self.TIMEOUT:
            self.setType('huawei')
            self.reconnect() # try next device type
        res=self.auth(login=user1,password=pass1)
        if res==self.TIMEOUT:
            return res
        if res!= telnetworker.TelnetWorker.AUTH_OK :
            for auth in self.authdata[1:]:
                self.reconnect() # try next password
                res=self.auth(user=auth['name'],password=auth['password'])
                if res==telnetworker.TelnetWorker.AUTH_OK :
                    break
        return res

    # auth at host   
    def auth(self,**kwargs): # {[login=login,] password=password}
        tn=self.tn
        ex=self.regarray
        index=4
        ret=0
        while (index in range(2,5)):
            index,value,text=tn.expect([ex['login_fail'],ex['prompt'],ex['password'],ex['login'],ex['more']],3) 
            if index==2: # if devise asks password
                tn.write(kwargs['password']+"\n")
            if index==3: # if devise asks login
                if 'login' in kwargs: # and we know login
                    tn.write(kwargs['login']+"\n")
                else: 
                    if self.debug &2 :
                        self.logbuffer.append('DEBUG: Error: we need login to %s'%(self.host))
                    ret=self.AUTH_NEED_LOGIN # we don't know login
                    break
            if index==4: # more
                tn.write(self.regarray['more_key'])    
            if index==0: # login_fail
                if self.debug :
                    self.logbuffer.append('ERROR: auth failed\n')
                ret=self.AUTH_REJECT 
                break
            if index==1: # prompt
                self.prompt=value.group(0).strip()  # and store prompt for defining equipment type
                self.password=kwargs['password']
                ret= self.AUTH_OK
                break
            if index==-1: 
                if self.debug :
                    self.logbuffer.append('ERROR: timeout at password\n')
                ret= self.TIMEOUT
                break
#        if self.debug:
#            flush_log(self.logbuffer)
        return ret


    # execute command and return output 
    def execute(self,command,timeout=3):
        escaped_commands=['display elabel'] #hack for brackets in huawei 'disp elabel' ans so on
        prompt=self.regarray['prompt']
        if command in escaped_commands:
            prompt=self.prompt
        if timeout==0:
            timeout=self.timeout
        tn=self.tn
        ex=self.regarray
        index=1
        answer=''
        status=self.COMMAND_OK #don't worry. be happy =)
        tn.write(command+'\n')
#        print 'executing...'
        while (index in [1,2,3,4]): # waiting while usefull prompt
            index,value,text=tn.expect([prompt,ex['yesno'],ex['more'],ex['extension'],ex["password"]],timeout)
            text=re.sub('\r\n','\n',ex['more_replace'].sub('',text))
            if index==1:
                if self.debug & 1:
                    self.logbuffer.append('<YES>\n')
                tn.write('y\n') # agree with all
            if index==2:
                tn.write(ex['more_key']) # want to see all
                text=text.replace(value.group(0),'')
            if index==3:
                tn.write('\n') # commit string
            if index==4:
                if self.debug & 1:
                    self.logbuffer.append('<password>\n')
                tn.write(self.password+'\n') # confirm string
            answer+=text
            if index==0:
                status=self.COMMAND_OK # yeah! =)
                if self.debug & 1:
                    self.logbuffer.append(answer)
                self.outbuffer.append(answer)
            if index==-1:
                if self.debug & 1:
                    self.logbuffer.append('Timeout at command %s\n'%(command))
                status=self.TIMEOUT # timeout. k.o.
#        if self.debug:
#            flush_log()
        return status

#    def flush_log():
#        for logline in self.logbuffer:
#            self.logfile.write(logline)
#        self.logfile.flush()
#        logbuffer[:]=[]

    #get output after last cleaning
    def extractBuffer(self):
        tmp=list(self.outbuffer)
        self.outbuffer[:]=[]
        return tmp

    def leave(self):
        self.tn.close()
#        if self.debug &2 :
#            self.logbuffer.append('DEBUG: closing connection')
#        flush_log()
#        self.logfile.close()


