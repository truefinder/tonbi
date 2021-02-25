# TONBI
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

-p  platform name 
    laravel, symfony, cakephp, codeigniter, fuelphp, phalcon, silex, yii, athena, flask, django, kivy, bottle, rails     
    
-h  display haed 3 line
-t  display tail 3 line 

```

## Customization
```
cat > db/example.json
kb {
    name : "example"
    xss { 
        key : "xxx" 
        description : "xxxxx"
        reference : "http://" 
    }
}

#tonbi -d ./src -p example -head -tail 

```
