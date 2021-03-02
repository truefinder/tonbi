# TONBI
<img src="https://user-images.githubusercontent.com/4240789/109131685-5fbdb500-7796-11eb-82d1-93237d83430c.jpg" width=250> 

TONBI is web source code auditing tool for security researchers, It supports various web application framework such as Laravel, Symfony, CakePHP, Codeigniter, ... 

_Waring : TONBI is not an full-automated auditing tool, but it gives you an efficient method for finding vulnerabilities of your framework based web applications 

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
-head <n> display haed n line
-tail <n> display tail n line 
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
==================================================
vulnerability : xss
description : FALSE may could occur xss, turn TRUE
reference : http://xxxxx.xxxx
filename : ../sample/codeigniter/lcb/app/application/config/config.production.php
=================================================
277: |
278: | Determines whether the XSS filter is always active when GET, POST or
279: | COOKIE data is encountered
280: |
281: */
282: $config['global_xss_filtering'] = FALSE;
283: 
284: /*
285: |--------------------------------------------------------------------------
286: | Cross Site Request Forgery
287: |--------------------------------------------------------------------------

==================================================
vulnerability : sql
description : direct sql summitting may occure sql injection 
reference : https://codeigniter.com/userguide3/database/queries.html
filename : ../sample/codeigniter/lcb/support/application/models/authenticate_model.php
=================================================
69:         }
70: 
71:         $this->session->set_userdata('username', $username);
72: 
73:         // Update privilege of session
74:         $query = $this->db->query(
75:             "UPDATE `ci_sessions` SET current_privilege=? WHERE session_id=?", array(
76:             'current_privilege' => $result[0]->privilege,
77:             'session_id'    => $this->session->userdata('session_id'),
78:         ));
79: 


```
