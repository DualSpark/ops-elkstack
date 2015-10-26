from setuptools import setup

setup(
    name="elkstack",
    version="0.1",
    install_requires=[
        'cfn-environment-base==0.8.2'
    ],
    dependency_links=[
        'https://github.com/DualSpark/cloudformation-environmentbase/archive/0.8.2.zip#egg=cfn-environment-base-0.8.2'
    ],
    package_dir={"": "src"},
    include_package_data=True,
    zip_safe=True
)
