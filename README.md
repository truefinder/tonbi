![pypi](https://img.shields.io/pypi/v/pybadges.svg)
![versions](https://img.shields.io/pypi/pyversions/pybadges.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)


# TONBI
<img src="https://user-images.githubusercontent.com/4240789/140497783-e7b4b21b-6272-4817-b495-5cc33d66b936.jpg" width=200>

## What's TONBI?


TONBI is a framework based web application source code auditing tool for security researchers. It supports various web application framework such as Laravel, Symfony, CakePHP, Codeigniter, ... It gives you an efficient auditing method for finding vulnerabilities of your web applications 


## Install 
Download tonbi from github 
```
git clone http://github.com/truefinder/tonbi.git 
```
Install yara-python 
```
$ pip install yara-python
```
But you can also get the source from GitHub and compile it yourself:
```
$ git clone --recursive https://github.com/VirusTotal/yara-python
$ cd yara-python
$ python setup.py build
$ sudo python setup.py install
```
Notice the --recursive option used with git. This is important because we need to download the yara subproject containing the source code for libyara (the core YARA library). It’s also important to note that the two methods above link libyara statically into yara-python. If you want to link dynamically against a shared libyara library use:
```
$ python setup.py build --dynamic-linking
```
## Basic Usage 
```
$python tonbi.py -d ./source_dir -f your_framework -l language 

```

## Options 
```
Usage: tonbi.py [options] args

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        set configuration file  ex) -c config.json
  -d DIRECTORY, --directory=DIRECTORY
                        set source directory ex ) -d /src
  -l LANGUAGE, --language=LANGUAGE
                        set language  ex) -l php
  -f FRAMEWORK, --framework=FRAMEWORK
                        set framework  ex) -p laravel
  -v VIEW, --view=VIEW  set render or view ex) -v smarty

  Output Options:
    -o OUTPUT, --output=OUTPUT
                        save result into file ex) -o output.txt
    -e EXCLUDE, --exclude=EXCLUDE
                        exclude some vulnerability ex) -e 'ssl_misconfiguration'
    --head=HEAD         show above lines ex) --head 5
    --tail=TAIL         show below lines ex) --tail 5

  Debug Options:
    -D, --debug         debug mode output of dbg_print
```

## Usage with configuration file 
create config.json like below

```
{
	"source_directory" : "../sample/codeigniter/src",
	"framework_name" : "codeigniter",
	"language" : "php", 
	"view_name" : "twig",
	"head_count" : 5,
	"tail_count" : 5,
	"output" : "output.txt",
	"plugins" : [  ],
	"ignore_files" :  [ "jpg", "png", "jpeg", "ico", "gif", "tif" , "tiff", "bmp",  "db", "css", "map", "md", "gitkeep", "sql", "DS_Store", "js", "propreties" , "csv", "gz", "tgz", "zip", "swf", "pyc", "phar" ], 
	"ignore_dirs" : ["node_modules"],
	"exclude" : ["ssl_misconfiguration"] 
}
```
And run tonbi
```
$python tonbi.py -c config.json 
```

## Frameworks 

 Supporting | laravel, codeigniter, django, flask,  gorilla, ethna, nodejs, rails  
----------- | ------------
 Planning   | symfony, fuelphp, cakePHP, silex, phalcon, express   


## Languages

 Supporting | go, php, javascript, python, typescript, ruby 
-----------|-----
 Planning   | jsp, asp, java, .NET   


## Viewes 

 Supporting | smarty, twig, blade, flexy, electron  
-----------|---------
 Planning   | react   


## Add your own foundings to framework
```
vi  framework/<framework_name>.yar
/* please read yara rule page  
 * https://yara.readthedocs.io/en/stable/writingrules.html
 */  

rule my_xss : <framework_name>  
{
    strings : 
        $xss1 = /render(.*false/ 
        $xss2 = /autoescape.*false/ nocase 
    condition:
        $xss1 or $xss2 
}
```

## Participate with your own plugin 
please create plugin file 
```
mkdir plugin/your_plugin
cat > plugin/your_plugin/your_plugin.py
```

And, please write class MyPlugin 
define three functions init(), audit(), finish()
```
class MyPlugin :
    def init(self):
        # firstly loaded 
    def audit(self, audititem):
        # called by every line 
	# audititem (class AuditItem) parametered to your audit()     
        #    .line <= (string) target string 
        #    .i <= (int) target line number 
        #    .filename <= (string) target filename  
        #    .lines <= (string) use this reference lines when you find out something  
        #    .output <= (Class Output) for your result, use output.list.append("your string") 
                    
    def finish(self)
        # please clear all resources when finished 
```

## Test 
```
==============================================
filename : ../targets/laravel/XXXX-Server/app/Libs/ImageMagic/Convert.php
dangerous php function : cmd_excute
dangerous matches : exec(
tag : php
==============================================
35:      * @return int
36:      */
37:     protected function executeCommand(string $command)
38:     {
39:         Log::debug(__METHOD__ . ' : ' . $command);
40:         exec($command .' 2>&1',$array, $code);
41:         if ($code !== 0) {
42:             // error
43:             $errorMsg = implode($array, "\n");
44:             Log::error(__METHOD__ . ' Convert failed. code: ' . $code);
45:             Log::error($errorMsg);
==================================================
filename : ../targets/laravel/ZZZZZ-server/resources/views/webview/information/index.blade.php
vulnerability : xss
matches : {!! $detail["information"] !!}
tag : laravel
=================================================
140:           @else
141:             <span id="info_new">NEW</span><br>
142:           @endif
143: 
144: 
145:           <span>{!! $detail["information"] !!}</span>
146:         </div>
147:       </a>
148:     </li>
149:     @endforeach
150:   </ul>



```
