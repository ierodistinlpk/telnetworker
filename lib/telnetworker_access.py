import re, telnetlib
#TODO: 
# full testing for alcatel and zyxel
class TelnetWorker:
    regexhash={
    'alcatel':{
        'prompt':re.compile("(.*)([\w\d\-\.\(\):>]*#)"),
        'login':re.compile("(?:login:)|(?:User name:)"),
        'password':re.compile("[Pp]assword:"),
        'login_fail':re.compile("(?:Login incorrect)|(?:Bad Password!!!)"),
        'fail':re.compile("invalid token",re.IGNORECASE),
        'more':re.compile("Press <space>\(page\).*\.\.\."), #Press <space>(page)/<enter>(line)/q(quit) to continue...
        'unknown':re.compile("command is not complete",re.IGNORECASE),
        'yesno':re.compile("[\[\(][Yy][es]{0,2}/[Nn]o*[\]\)]",re.IGNORECASE), ####### NOT READY!!!
        'more_key':' ',
        'more_replace':re.compile("\x1b\[80D *\x1b\[80D"),
        'extension':re.compile("(\{.+\}:)")
        },
    # ma5605, ma5600, ua5000
    'huawei':{
        'prompt':re.compile("\n([\w\d\-\.\(\)]+[>#%])"),
        'login':re.compile("\>*(?:[uU]ser name(?: \(<20 chars\))?:)"),
        'password':re.compile("[Pp]assword.*:"),
        'login_fail':re.compile('(?:Login fail.?)|(?:Username.*invalid.?)'),
        'fail':re.compile("(Failure:.*)",re.IGNORECASE),
        'more':("([- ]+[Mm]ore.*----)"),
        'unknown':re.compile("([% ]*((?:Incorrect)|(?:Unknown) command).*)",re.IGNORECASE),
        'yesno':re.compile("\([Yy]/[Nn]\) *\[[YyNn]\]",re.IGNORECASE),
        'more_key':' ',
        'more_replace':re.compile(".*\x1b\[37D\x1b\[1A"),
        'extension':re.compile("(\{.+\}:)")
        },
    # es-3124 NOT READY
    'zyxel':{
        'prompt':re.compile("\n([\w\d\-\.\(\)]+[>#%])"),
        'login':re.compile("(?:[uU]ser name:)"),
        'password':re.compile("[Pp]assword:"),
        'login_fail':re.compile("(?:logon failed.)|(?:Bad Password!!!)"),
        'fail':re.compile("(ERROR:.*)",re.IGNORECASE), ### NOT READY
        'more':re.compile("([- ]+[Mm]ore.*)"),
        'unknown':re.compile("([% ]\n*(?:Invalid)(?:Incomplete) command.*)\n",re.IGNORECASE),
        'yesno':re.compile("\([Yy]/[Nn]\) *[YyNn]",re.IGNORECASE), ### NOT READY
        'more_key':'c',
        'more_replace':re.compile("\x08*"),
        'extension':re.compile("(\{.+\}:)")
        },
    #aes-*, ies-* NOT READY
    'zyxel_dslam':{
        'prompt':re.compile("\n([\w\d\-\.\(\)]+[>#%])"),
        'login':re.compile("[uU]ser name:"),
        'password':re.compile("[Pp]assword:"),
        'login_fail':re.compile("(?:logon failed.)|(?:Bad Password!!!)"),
        'fail':re.compile("(ERROR:.*)",re.IGNORECASE), ### NOT READY
        'more':"press 'e' to exit showall, 'n' for nopause, or any key to continue...",
        'unknown':re.compile("(\n.*: invalid command.*\n)",re.IGNORECASE),
        'yesno':re.compile("\([Yy]/[Nn]\) *[YyNn]",re.IGNORECASE), ### NOT READY
        'more_key':'n',
        'more_replace':re.compile("\x08*"),
        'extension':re.compile("(\{.+\}:)")
        }

    }
    AUTH_OK=0
    TIMEOUT=-1
    AUTH_REJECT=10
    AUTH_NEED_LOGIN=20
    COMMAND_OK=0
    COMMAND_FAIL=1
    COMMAND_UNKNOWN=2
    def __init__(self, host, typ, timeout=5):
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
            self.tn.close()
        self.tn.open(self.host,23)

    def setType(self,typ):
        self.type=typ
        self.regarray=self.regexhash[typ]
        
    # auth at host   
    def auth(self,**kwargs): # {[login=login,] password=password}
        tn=self.tn
        ex=self.regarray
        index=0
        ret=0
        while (1):#(index < 3):
            index,value,text=tn.expect([ex['password'],ex['login'],ex['more'],ex['login_fail'],ex['prompt']],3) 
            #print text
            #print index
            if index==0: # if devise asks password
                tn.write(kwargs['password']+"\n")
            if index==1: # if devise asks login
                if 'login' in kwargs: # and we know login
                    tn.write(kwargs['login']+"\n")
                else: 
                    self.logbuffer.append('\nError: we need login to %s'%(self.host))
                    ret=self.AUTH_NEED_LOGIN # we don't know login
                    break
            if index==2: # more
                tn.write(self.regarray['more_key'])    
            if index==3: # login_fail
                self.logbuffer.append('Error: auth failed\n')
                ret=self.AUTH_REJECT 
                break
            if index==4: # prompt
                self.prompt=value.group(0).strip()  # and store prompt for defining equipment type
                self.password=kwargs['password']
                ret= self.AUTH_OK
                break
            if index==-1: 
                self.logbuffer.append('Error: timeout at password\n')
                ret= self.TIMEOUT
                break
        return ret


    # execute command and return output 
    def execute(self,command,timeout=0):
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
        while (index in [1,2,3,4]): # waiting while usefull prompt
            index,value,text=tn.expect([prompt,ex['yesno'],ex['more'],ex['extension'],"[Pp]assword.*:"],timeout)
            text=re.sub('\r\n','\n',ex['more_replace'].sub('',text))
            if index==1:
                tn.write('y\n') # agree with all
            if index==2:
                tn.write(ex['more_key']) # want to see all
                text=text.replace(value.group(0),'')
            if index==3:
                tn.write('\n') # commit string
            if index==4:
                tn.write(self.password+'\n') # commit string
            answer+=text
            if index==0:
                status=self.COMMAND_OK # yeah! =)
                self.outbuffer.append(answer)
                if ex['unknown'].match(text) is not None:
                    self.logbuffer.append('Warning:'+text+'\n')
                    status=self.COMMAND_UNKNOWN # what??? :0
                    break
                if ex['fail'].match(text) is not None: 
                    self.logbuffer.append('Warning:'+text+'\n')
                    status=self.COMMAND_FAIL #fuck :(
                    break
            if index==-1:
                self.logbuffer.append('Timeout at command %s\n'%(command))
                status=self.TIMEOUT # timeout. k.o.
        return status

    # execute command and return output 
    def execute_long(self,command,timeout=60):
        escaped_commands=[] #hack for brackets in huawei 'disp elabel' ans so on
        prompt=self.regarray['prompt']
        tn=self.tn
        ex=self.regarray
        index=1
        timeup=0
        answer=''
        status=self.COMMAND_OK #don't worry. be happy =)
        tn.write(command+'\n')
        while (index in [0,1,2,3,4,-1]): # waiting while usefull prompt
            index,value,text=tn.expect([prompt,ex['yesno'],ex['more'],ex['extension'],"[Pp]assword.*:"],timeout)
            text=re.sub('\r\n','\n',ex['more_replace'].sub('',text))
            if index==1:
                tn.write('y\n') # agree with all
            if index==2:
                tn.write(ex['more_key']) # want to see all
                text=text.replace(value.group(0),'')
            if index==3:
                tn.write('\n') # commit string
            if index==4:
                tn.write(self.password+'\n') # commit string
            if index>=0 and timeup==0:
                answer+=text
            if index==0 and timeup==1:
                self.outbuffer.append(answer)
                status=self.COMMAND_OK # yeah! =)                
                break
            if index==-1:
                timeup=1
                tn.write('\n')
                status=self.TIMEOUT # timeout. k.o.
        return status
        
    #get output after last cleaning
    def extractBuffer(self,buf='out'):
        bufs={'out':self.outbuffer,'log':self.logbuffer}
        tmp=list(bufs[buf])
        bufs[buf][:]=[]
        return tmp

    def leave(self):
        self.tn.close()

