Completion
========================

### bash completion

1. install bash-completion as follows:

 ```
 % sudo apt-get install bash-completion
 ```

1. add gobgp's path to PATH environment variable

 If you run 'go get github.com/osrg/gobgp/gobgp', gobgp command is installed in $GOPATH/bin.
 ```
 % export PATH=$PATH:$GOPATH/bin
 ```

1. load completion file

 ```
 % source $GOPATH/src/github.com/osrg/gobgp/tools/completion/gobgp-completion.bash
 ```

You can use tab completion for gobgp after loading gobgp-completion.bash.



### zsh completion

zsh completion for gobgp works by adding the path of gobgp zsh completion directory to $fpath and enabling zsh completion like below:

 ```
 % vi ~/.zshrc

 GOBGP_COMP=$GOPATH/src/github.com/osrg/gobgp/tools/completion/zsh
 fpath=($GOBGP_COMP $fpath)

 autoload -Uz compinit
 compinit

 ```