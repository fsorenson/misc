

## About bashrc.d

This directory contains short bash scripts that are sourced from .bashrc, defining bash functions, setting variables, aliases, etc., in the same way that /etc/bashrc sources the files in ```/etc/profile.d/*.sh```

## Use

Create the ```$HOME/.bashrc.d``` directory
```mkdir ~/.bashrc.d```

Add bash scripts to the ```$HOME/.bashrc.d``` directory, with a ```.sh``` extension


Include the following in ```$HOME/.bashrc```
```
for f in ~/.bashrc.d/*.sh /dev/null ; do
        [[ -r "$f" ]] && {
                . "$f"
        }
done
```
