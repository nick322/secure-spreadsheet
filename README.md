# Secure Spreadsheet

🔥 Secure your data exports - encrypt and password protect sensitive XLSX files

The [Office Open XML format](https://en.wikipedia.org/wiki/Office_Open_XML) provides a standard for encryption and password protection

Works with Excel, Numbers, and LibreOffice Calc

[![Build Status](https://github.com/nick322/secure-spreadsheet/workflows/tests/badge.svg?branch=master)](https://github.com/nick322/secure-spreadsheet/actions)

## Installation

To install the package:

Run ``composer require nick322/secure-spreadsheet`` to add the package to your project.

Or run ``composer global require nick322/secure-spreadsheet`` to add the package to your system.

This will automatically install the package to your vendor folder.

## Use

In cli

```bash
secure-spreadsheet run --password=1 --input=/Users/nick/Encryptor/Book1.xlsx --output=/Users/nick/Encryptor/bb.xlsx

```

In php

```php
require "vendor/autoload.php";

use Nick\SecureSpreadsheet\Encrypt;

$test = new Encrypt();
$test->input('Book1.xlsx')
    ->password('111')
    ->output('bb.xlsx');
```


If you want to only use memory/variable output and input, and no file interaction
```php
$test = new Encrypt($nofile = true);
$output = $test->input($binaryData)
    ->password('111')
    ->output();
```

## Credits

Thanks to [xlsx-populate](https://github.com/dtjohnson/xlsx-populate) for providing the encryption and password protection.

## History

View the [changelog](https://github.com/nick322/secure-spreadsheet/blob/master/CHANGELOG.md)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/nick322/secure-spreadsheet/issues)
- Fix bugs and [submit pull requests](https://github.com/nick322/secure-spreadsheet/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features

To get started with development:

```sh
git clone https://github.com/nick322/secure-spreadsheet.git
cd secure-spreadsheet
./secure-spreadsheet
```
