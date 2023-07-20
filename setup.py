from setuptools import setup

setup(
    name='urlscan',
    version='1.0.0',
    description='Your package description',
    author='Your Name',
    author_email='your@email.com',
    url='https://github.com/your_username/your_package',
    packages=['src'],
    entry_points={
        'console_scripts': [
            'urlscan = src.__main__:main',
        ],
    },
    install_requires=[
        'requests',
        'python-dotenv'
    ],
)

# python setup.py sdist bdist_wheel
