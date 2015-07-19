from setuptools import setup

setup(
    name="elkstack",
    version="0.1",
    install_requires=[
        'cfn-environment-base'
    ],
    dependency_links=[
        'https://github.com/DualSpark/cloudformation-environmentbase/zipball/master#egg=cfn-environment-base'
    ],
    package_dir={"": "src"},
    entry_points={
        'console_scripts': ['elkstack=elkstack:main']
    }
)
