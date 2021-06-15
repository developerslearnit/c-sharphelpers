# C-Sharp Helpers
This package comprises of collections of C# helper methods that are used every day by c-sharp developers. You don't have to write these helper functions yourself. There are currenlty eleven helper methods - still growing.

Helpers
---------------
### Helpers.Right(int length) - Get substring of specified number of characters on the right. 

Usage

```
var longString = "abcdefghijklmnopqrstuvwxyz";

var lastFourXters = longString.Right(4);

```

### Helpers.Left(int length) - Get substring of specified number of characters on the left. 

Usage

```
var longString = "abcdefghijklmnopqrstuvwxyz";

var lastFourXters = longString.Left(4);

```

### Helpers.ToBase64() - Convert a given value to base64 string. 

Usage

```
var name = "MarkAdesina";

var base64 = name.ToBase64();

```

### Helpers.FromBase64() - Convert baase64 string to normal string. 

Usage

```
var name = "somebase64string";

var rawString = name.FromBase64();

```
