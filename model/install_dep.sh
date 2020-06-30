export VIRTUALENVWRAPPER_PYTHON=$(which python3)
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
workon angr
#add new dependency here
pip install dgl
pip install torch==1.5.1+cpu -f https://download.pytorch.org/whl/torch_stable.html