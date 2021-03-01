# TONBI
<img src="https://user-images.githubusercontent.com/4240789/109131685-5fbdb500-7796-11eb-82d1-93237d83430c.jpg" width=250> 

TONBI is web source code auditing tool for security researchers, It supports various web applications based on sever-side platform such as Laravel, Symfony, CakePHP, ... 

_Waring : TONBI is not an all-automated tool, but give you an efficient method for full manual source code auditing  

## Install 
Download tonbi 
```
git clone http://github.com/truefinder/tonbi.git 
```

## Usage 
```
$tonbi -d <source> -p <platform> -t <template> --head <num> --tail <num> -o result.txt

-d <source> top source code directory
-p <paltform> server-side platform name     
-t <template> view template name
-head <n> display haed 3 line
-tail <n> display tail 3 line 
-o <output> save result into text file

```

## Supported platform 
* PHP
    - laravel, symfony, cakephp, codeigniter, fuelphp, phalcon, silex, yii, ethena
* Python
    - flask, django, kivy, bottle
* Ruby
    - rails 


## Adding your own foundings to KBDB
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


$tonbi -d ./src -p example --head 3 --tail 3 -o result.txt

```

## Result 
```
================================================
 vulnerability : sql
 description : direct sql summitting may occure sql injection 
 reference : https://codeigniter.com/userguide3/database/queries.html
 filename : ../sample/codeigniter/lcb/app/system/database/DB_forge.php
================================================
		return $this->db->query($sql);

================================================
 vulnerability : xss
 description : FALSE may could occur xss, turn TRUE
 reference : http://xxxxx.xxxx
 filename : ../sample/codeigniter/lcb/app/application/config/config.mj.php
================================================
$config['global_xss_filtering'] = FALSE;

================================================
 vulnerability : debug
 description : TRUE may show debug message to an attacker 
 reference : http://yyyyyy.yyyyy
 filename : ../sample/codeigniter/lcb/app/application/config/database.php
================================================
$db['default']['db_debug'] = TRUE;

================================================
 vulnerability : xss
 description : FALSE may could occur xss, turn TRUE
 reference : http://xxxxx.xxxx
 filename : ../sample/codeigniter/lcb/app/application/config/config.php
================================================
$config['global_xss_filtering'] = FALSE;

================================================
 vulnerability : xss
 description : FALSE may could occur xss, turn TRUE
 reference : http://xxxxx.xxxx
 filename : ../sample/codeigniter/lcb/app/application/config/config.production.php
================================================
$config['global_xss_filtering'] = FALSE;

================================================
 vulnerability : xss
 description : FALSE may could occur xss, turn TRUE
 reference : http://xxxxx.xxxx
 filename : ../sample/codeigniter/lcb/config/settings/app/application/config/config.php
================================================
$config['global_xss_filtering'] = FALSE;

================================================
 vulnerability : debug
 description : TRUE may show debug message to an attacker 
 reference : http://yyyyyy.yyyyy
 filename : ../sample/codeigniter/lcb/support/application/config/database.php
================================================
$db['default']['db_debug'] = TRUE;

================================================
 vulnerability : csrf
 description : FALSE may occur csrf, turn TRUE
 reference : https://codeigniter.com/userguide3/libraries/security.html
 filename : ../sample/codeigniter/lcb/support/application/config/config.php
================================================
$config['csrf_protection'] = FALSE;

================================================
 vulnerability : sql
 description : direct sql summitting may occure sql injection 
 reference : https://codeigniter.com/userguide3/database/queries.html
 filename : ../sample/codeigniter/lcb/support/application/models/authenticate_model.php
================================================
        $query = $this->db->query(


```
