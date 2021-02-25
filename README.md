# TONBI
![Alt トンビ](https://user-images.githubusercontent.com/4240789/109131685-5fbdb500-7796-11eb-82d1-93237d83430c.jpg)

TONBI is web source code auditing tool for security researchers, It supports various web applications based on sever-side platform such as Laravel, Symfony, CakePHP, ... 

_Waring : TONBI is not an all-automated tool, but give you an efficient method for full manual source code auditing for your web systems_ 

## Install 
Download tonbi 
```
git clone http://github.com/truefinder/tonbi.git 
```

## Usage 
```
$tonbi -d <source> -p <platform> -head -tail 

-d  source directory
-p  platform name     
-h  display haed 3 line
-t  display tail 3 line 

```

## Supported platform 
* PHP
    - laravel, symfony, cakephp, codeigniter, fuelphp, phalcon, silex, yii, ethena
* Python
    - flask, django, kivy, bottle
* Ruby
    - rails 


## Customization
```
mkdir platform/exmaple 
cat > platform/example/kbdb.json
{
	plugin : "example"
	version : "3"
	items : 
	[ 
		{
			vulnerability : "xss"  ,
			keyword : ["appView(" ] , 
			description : "appView function displays non-sanitized input data from user" , 
			reference : "http://xxxxx.xxxx" 
		},

		{
			vulnerability : "cmd" ,
			keyword : ["excuteCmd((" ]
			description : "excuteCmd function excute cli on server ", 
			reference : "http://yyyyyy.yyyyy" 
		}
	]
}


$tonbi -d ./src -p example -head -tail 

```
