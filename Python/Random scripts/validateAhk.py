# This Python file uses the following encoding: utf-8
import sys, getopt, re, os

invalid_commands = {
    'Shutdown': re.compile(r'\bShutdown\b', re.IGNORECASE),
    'DllCall' : re.compile(r'\bDllCall\b', re.IGNORECASE),
    'RegWrite' : re.compile(r'\bRegWrite\b', re.IGNORECASE),
    'RegDelete' : re.compile(r'\bRegDelete\b', re.IGNORECASE),
    'UrlDownloadToFile' : re.compile(r'\bUrlDownloadToFile\b', re.IGNORECASE),
    'iniRead' : re.compile(r'\biniread\b', re.IGNORECASE),
    'iniDelete' : re.compile(r'\biniDelete\b', re.IGNORECASE),
    'iniWrite' : re.compile(r'\biniWrite\b', re.IGNORECASE),
    'process' : re.compile(r'\bprocess\b', re.IGNORECASE),
    'registerCallBack' : re.compile(r'\bregistercallback\b', re.IGNORECASE),
    'sysGet' : re.compile(r'\bsysget\b', re.IGNORECASE),
    'FileCreateDir' : re.compile(r'\bFileCreateDir\b', re.IGNORECASE),
    'FileMove' : re.compile(r'\bFileMove\b', re.IGNORECASE),
    'FileAppend' : re.compile(r'\bFileAppend\b', re.IGNORECASE),
    'FileDelete' : re.compile(r'\bFileDelete\b', re.IGNORECASE),
    'RawWrite' : re.compile(r'\bRawWrite\b', re.IGNORECASE),
    
}

allowed_commands = {
    'Run': re.compile(r'\bRun\b', re.IGNORECASE),
    'Exe': re.compile(r'\bexe\b', re.IGNORECASE),         
    'Com' : re.compile(r'\bCom\b', re.IGNORECASE),
    '.ahk' : re.compile(r'\b\.ahk\b', re.IGNORECASE),
    
}
'''
Varje keyword kan ha flera strängar som är whitelistade
Tex url'er till Run kommandot
'''
rWeb = r'[,\s]\b((http|https):\/\/)?(\w+\.)?' #regexuttryck för webbadress

white_list = {
    '.ahk': [
		re.compile(r'Include[\s]L:\\autohotkey\\+(\w)?', re.IGNORECASE),
	
		],

     'Exe': [
        re.compile(r'[,\s]acrord32[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]calc[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]excel[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]magnify[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]notepad[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]powerpnt[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]onenote[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]outlook[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]skype[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]snippingtool[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]winword[\.exe]?', re.IGNORECASE),
        
        ],
		
  
    'Run': [
        re.compile(r'[,\s]acrord32[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]calc[\.exe]?', re.IGNORECASE),
		re.compile(r'[,\s]excel[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]magnify[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]notepad[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]powerpnt[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]onenote[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]outlook[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]skype[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]snippingtool[\.exe]?', re.IGNORECASE),
        re.compile(r'[,\s]winword[\.exe]?', re.IGNORECASE),
        
        ]
}

black_list = {
    'Run': [
        re.compile(rWeb + r'icloud\.com*', re.IGNORECASE),
        re.compile(rWeb + r'drive\.google\.com*', re.IGNORECASE), 
        re.compile(rWeb + r'docs\.google\.com*', re.IGNORECASE),
        re.compile(rWeb + r'onedrive\.live\.com*', re.IGNORECASE),
        re.compile(rWeb + r'dropbox\.com*', re.IGNORECASE)
        
        ]
}
'''
Listar alla filer som har .ahk extension
Letar i subdirectories också
'''
def listfiles (directory):
    filelist = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.ahk'):
                filelist.append(os.path.join(root, file))

    return filelist

'''
Läser en fil och letar efter suspicious keywords
'''
def readFile (inputfile):
    returnCode = 0
    resultTxt = "\n-- Analyserar filen: " + inputfile + " --"
    warningTxt = ""
    with open(inputfile, errors='ignore') as fp:
        i = 0
        keywordFound = False
        commentFlag = False
        for line in fp:
            i += 1
            if line.strip().startswith(r'/*'):# Flagga för block-comment
                commentFlag = True
             
            if line.strip().startswith(r'*/'):# Avflagga för blockcomment
                commentFlag = False

            if not commentFlag == True:
                if not line.strip().startswith(";"):# Analysera inte kommentarer med semikolon
                    key, match = analyzeInvalidCommands (line)
                    if (key != None):
                        keywordFound = True
                        warningTxt += "\nRad " + str(i) + ": " + line.strip() + " <- Otillåtet scriptkommando"

                    key, match = analyzeAllowedCommands (line)
                    if (key != None):
                        keywordFound = True
                        warningTxt += "\nRad " + str(i) + ": " + line.strip() + " <- Otillåten webbadress och eller otillåtet programanrop"

    if not keywordFound:
        resultTxt += " Ok"
    else:
        resultTxt += "\nIdentifierade scriptrader som nekar automatiskt godkännande/uppladdning:" + warningTxt
        returnCode = 1
    return [resultTxt, returnCode]

def analyzeInvalidCommands( line ):
    for key, reg in invalid_commands.items():
        match = reg.search(line)
        if match:
            return key, match

	# Om inga träffar
    return None, None

def analyzeAllowedCommands( line ):
    for key, reg in allowed_commands.items():
        match = reg.search(line)
        if match:
            if blackListed(key, line):
                return key, match
            
            if not whiteListed(key, line):
                x = str(re.search('http|www|\.se$|\.nu$|\.net$|\.com$', line))
                if (x != "None"):
                    return None, None
                else:
                    return key, match
	
	# Om inga träffar
    return None, None

def whiteListed(key, line):
    if key in white_list:
        whiteListedArr = white_list.get(key)
        for reg in whiteListedArr:
            match = reg.search(line)
            if match:
                return True
    return False

def blackListed(key, line):
    if key in black_list:
        blackListedArr = black_list.get(key)
        for reg in blackListedArr:
            match = reg.search(line)
            if match:
                return True
    return False

def main(argv):
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv, "hf:d:")
    except getopt.GetoptError:
        print ('Usage: validateAhk.py -i <file,file2,file..n> | -d <directory>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: validateAhk.py -i <file,file2,file..n> | -d <directory>')
            sys.exit()
        elif opt in ("-f"):
            files = arg.split(",")
            for file in files:
                result = readFile (file)
                print (result[0])
                sys.exit(result[1])
        elif opt in ("-d"):
            returnCode = 0
            files = listfiles (arg)
            for file in files:
                result = readFile (file)
                print (result[0])
                returnCode = result[1]

            sys.exit(returnCode)

if __name__ == "__main__":
    main(sys.argv[1:])
