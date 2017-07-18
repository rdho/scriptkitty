#! /bin/bash

# my local profile env setup for ubuntu server
sudo apt-get update
sudo apt-get -y install vim htop unzip zsh git-core ntp build-essential iftop screen
wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh
sed -i '/ZSH_THEME=/s/\"robbyrussell"/"pygmalion"/' ~/.zshrc
echo "export LC_CTYPE=en_US.UTF-8" >> ~/.zshrc
touch ~/.vimrc
echo -e "syntax on\nset background=dark\nset tabstop=2 shiftwidth=2 expandtab\nset hlsearch" > ~/.vimrc
sudo apt-get clean
chsh -s `which zsh`