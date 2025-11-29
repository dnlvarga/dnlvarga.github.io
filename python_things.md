#python2
Installation of Python2.7:
```
curl https://pyenv.run | bash
```
Or if that version is already installed, we can directly use the 
```
pyenv shell 2.7
```
command to use python2.7.

#virtual environment
```
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install numpy==1.26.4
pip install matplotlib==3.7.2
```
