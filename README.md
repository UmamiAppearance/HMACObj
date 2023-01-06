# HMACObj

[![License](https://img.shields.io/github/license/UmamiAppearance/HMACObj?color=009911&style=for-the-badge)](./LICENSE)
[![npm](https://img.shields.io/npm/v/hmac-obj?color=%23009911&style=for-the-badge)](https://www.npmjs.com/package/hmac-obj)


**HMACObj** creates a HMAC-SHA-(1/256/384/512) object. It is related to [pythons hmac libary](https://docs.python.org/3/library/hmac.html) in its methods and features but with many extras. It provides an easy access to the ``Crypto.subtle`` method provided by modern browsers and node.js.  
  
Optionally it possible to get multiple different digest methods with a little help of [BaseEx](https://github.com/UmamiAppearance/BaseExJS). **BaseEx** also enables the feature to feed the HMAC Object with not just byte-like input but almost any type available in JavaScript. 


## Installation

### GitHub
```sh
git clone https://github.com/UmamiAppearance/HMACObj.git
```

### npm
```sh
nmp install hmac-obj
```

## Builds
You can find builds in [dist](https://github.com/UmamiAppearance/HMACObj/tree/main/dist). Builds include versions with BaseEx build in and without the library. Two types for both kinds are available ([esm](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules) and [iife](https://developer.mozilla.org/en-US/docs/Glossary/IIFE)), plus a minified version of each.  
  
If you want to build it by yourself run:

```sh
npm run build
```

#### Builds with BaseEx included
* [``hmac-obj-bex.esm.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj-bex.esm.js)
* [``hmac-obj-bex.esm.min.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj-bex.esm.min.js)
* [``hmac-obj-bex.iife.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj-bex.iife.js)
* [``hmac-obj-bex.iife.min.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj-bex.iife.min.js)

#### Builds without BaseEx _(You have to make sure `BaseEx` is globally available)_
* [``hmac-obj.esm.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj.esm.js)
* [``hmac-obj.esm.min.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj.esm.min.js)
* [``hmac-obj.iife.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj.iife.js)
* [``hmac-obj.iife.min.js``](https://raw.githubusercontent.com/UmamiAppearance/HMACObj/main/dist/hmac-obj.iife.min.js)



## Usage

### Importing

#### node.js

##### esm
```js
import HMACObj from "hmac-obj";
```

##### cjs
```js
const HMACObj = require("hmac-obj");
```


#### Browser

##### esm
```js
import HMACObj from "./path/hmac-obj-bex.esm.min.js";
```

##### esm from CDN (jsdelivr)
```js
import HMACObj from "https://cdn.jsdelivr.net/npm/hmac-obj@latest/dist/hmac-obj-bex.esm.min.js"
```

##### iife script tag
```html
<script src="./path/hmac-obj-bex.iife.min.js"></script>
```

##### iife script tag from CDN (jsdelivr)
```html
<script src="https://cdn.jsdelivr.net/npm/hmac-obj@latest/dist/hmac-obj-bex.iife.min.js"></script>
```

### Creating an instance    
The constructor takes one argument for the ``digestmod``. Available options are:
* ``SHA-1``
* ``SHA-256``
* ``SHA-384``
* ``SHA-512``

There a two possible ways available to create an instance:

#### the new operator
```js
const hmacSHA256 = new HMACObj("SHA-256");
```

#### the new method
This method is asynchronous to allow you to associate a message in one go.
```js
const hmacSHA512 = await HMACObj.new("super_secret_key", "Hello World!", "SHA-512");
```


### Methods and Properties

#### Static

##### ``HMACObj.digestmodsAvailable()``
A set containing the names of the hash algorithms that are available.

##### ``HMACObj.keyFormats()``
Static method to receive a set of the available key formats.

##### ``HMACObj.new(key=null, msg=null, digestmod="", keyFormat="raw", permitExports=false)``
Asynchronously creates a new instance. In contrast to the regular [new operator](#new-operator) a message and key can  be provided. If a message is set, a key must also be handed over or a crypto key gets generated automatically.  
  
A message gets passed to the [``update``](#updateinput-replacefalse) method.

##### ``HMACObj.generateKey(digestmod=""[, permitExports=false])``
Static asynchronous method to generate a crypto key for the HMAC algorithm.

##### ``HMACObj.compareDigest(a, b)``
Return ``a === b``. This function uses an approach designed to prevent timing analysis by avoiding content-based short circuiting behavior, making it appropriate for cryptography.  

``a`` and ``b`` (or more precisely their byte representation) must both be of the same type.

##### ``HMACObj.baseEx`` _[object]_
A [BaseEx Instance](https://github.com/UmamiAppearance/BaseExJS#available-converterscharsets) for the possibility to manually convert (byte) representations.

#### Instance

##### ``digestSize`` _[property]_
The size of the resulting HMAC in bytes.

##### ``blockSize`` _[property]_
The internal block size of the hash algorithm in bytes.

##### ``name`` _[property]_
The canonical name of this HMAC, always uppercase and always suitable as a parameter to create another HMAC of this type.

##### ``update(input[, replace=false])``
Update the HMAC object with almost any input. The input gets converted to a ``Uint8Array``. Unless ``replace`` is set to true, repeated calls are equivalent to a single call with the concatenation of all the arguments:  
``hmacObj.update(a)``; ``hmacObj.update(b)`` is in many occasions equivalent to ``hmacObj.update(a+b)``.  
  
_(Note: The process is a concatenation of bytes. Take as an exception for instance ``hmacObj.update(1)``; ``hmacObj.update(2)``, which is not the same as ``hmacObj.update(1+2)``)_

##### ``replace(input)``
Replace the the HMAC object with fresh input (the same as ``update(input, true)``).

##### ``sign(msg, base=null)``
Signs a single message independent from the current instance message. If a base is provided, the key gets returned in the corresponding [base representation](https://umamiappearance.github.io/HMACObj/examples/live-examples.html#base-representations).

##### ``verify(msg, signature)``
A given message (``msg``) and ``signature`` can be tested if it is signed with the current instance crypto key.

##### ``setKey(cryptoKey)``
Method to set or replace the associated crypto key. The key must be as provided of the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey).

##### ``generateKey(permitExports=true)``
Like the [static method](#hmacobjgeneratekey), with the difference, that the key is not returned but assigned to the instance. By default the key is exportable.

##### ``importKey(key[, format="raw", permitExports=false])
Import a Crypto Key from almost any input or a pre existing key.

##### ``exportKey(format="raw")``
Exports the Crypto Key assigned to the instance, if it is an exportable key.

##### ``digest()``
Return the digest of the data passed to the [``update``](#updateinput-replacefalse) method so far. This is an ``ArrayBuffer`` of size [``digestSize``](#digestsize-property).

##### ``hexdigest()``
Like [``digest``](#digest) except the digest is returned as a string of double length, containing only hexadecimal digits. This may be used (as one of many options) to exchange the value safely in non-binary environments.

##### ``basedigest`` _(object)_
Provides many different methods to convert the digest into different base representations. Take a look at the [live-examples](https://umamiappearance.github.io/HMACObj/examples/live-examples.html#base-representations), to see it in action.  
Every ``basedigest`` optionally takes additional [BaseEx Parameters](https://github.com/UmamiAppearance/BaseExJS#options).

##### ``copy()``
Async method to return a copy/clone of the HMAC object. This can be used to efficiently compute the digests of data sharing a common initial substring.


## Examples
[Here](https://umamiappearance.github.io/HMACObj/examples/live-examples.html) you can find many live-examples. To get a better idea of a possible use case, take a look at the [Online HMAC Generator](https://umamiappearance.github.io/HMACObj/examples/generator.html).


## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2023, UmamiAppearance
