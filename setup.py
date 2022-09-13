from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='cloudgenix_config',
      version='1.7.0b3',
      description='Configuration exporting and Continuous Integration (CI) capable configuration importing for the '
                  'CloudGenix Cloud Controller.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/CloudGenix/cloudgenix_config',
      author='CloudGenix Developer Support',
      author_email='developers@cloudgenix.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 6.0.1b1, < 6.0.2b1',
            'PyYAML >= 5.3'
      ],
      packages=['cloudgenix_config'],
      entry_points={
            'console_scripts': [
                  'do_site = cloudgenix_config.do:go',
                  'pull_site = cloudgenix_config.pull:go',
                  ]
      },
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8"
      ]
      )
