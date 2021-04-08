# TONBI
<img src="https://user-images.githubusercontent.com/4240789/109131685-5fbdb500-7796-11eb-82d1-93237d83430c.jpg" width=250> 

## What's TONBI?
TONBI is a framework based web application source code auditing tool for security researchers. It supports various web application framework such as Laravel, Symfony, CakePHP, Codeigniter, ... It gives you an efficient auditing method for finding vulnerabilities of your web applications 

## Install 
Download tonbi 
```
git clone http://github.com/truefinder/tonbi.git 
```

## Basic Usage 
```
$tonbi -d ./source_dir -p your_platform --head 3 --tail 3 -o output.txt
```

## Options 
```
-d <source> top source code directory
-p <paltform> server-side platform name     
-t <template> view template name
-head <n> display haed n line
-tail <n> display tail n line 
-o <output> save result into text file
-D verbose output
-c use config file

```

## Usage with config.json
create config.json like below

```
{
	"source_directory" : "../sample/codeigniter/src",
	"platform_name" : "codeigniter",
	"head_count" : 5,
	"tail_count" : 5,
	"template_name" : "",
	"output" : "output.txt",
	"plugins" : [ "php" ],
	"ignore_files" :  [ "jpg", "png", "jpeg", "ico", "gif", "tif" , "tiff", "bmp" ] 
	"ignore_dirs" : ["node_modules"] 
}

$python tonbi.py -c config.json 
```

## Platforms & Templates
* Laravel 
* Codeigniter
* Django
* Flask
* Typescript 
* Gorilla

## Plugins & Language 
* php 
* python
* go
* nodejs 

## Update Plans 
* PHP
    - symfony, cakephp, fuelphp, phalcon, silex, yii, ethna, 
* Python 
    - kivy, bottle
* Ruby
    - rails 
* Javascript 
    - scala 


## Add your own foundings to tonbi
```
touch platform/some_platform.yar 
cat > platform/some_platform.yar
/* some_platform vulnerable code audting rule */  
{
rule code_injection : some_platform 
{
    strings : 
        $code1 = "exec(" 
        $code2 = /yml\.load\(.*yaml\.Loader/
    condition:
        $code1 or $code2 
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
