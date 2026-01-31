from setuptools import setup, find_packages

setup(
    name='nullsec-gpt',
    version='1.0.0',
    description='AI-powered vulnerability scanner & security assistant',
    author='bad-antics',
    author_email='bad-antics@github.com',
    url='https://github.com/bad-antics/nullsec-gpt',
    py_modules=['nullsec_gpt'],
    entry_points={
        'console_scripts': [
            'nullsec-gpt=nullsec_gpt:main',
        ],
    },
    install_requires=[
        'openai>=1.0.0',
    ],
    extras_require={
        'full': ['requests', 'pyyaml'],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
)
