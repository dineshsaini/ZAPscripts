use first enrty in dictionary in username and password as worng or blank,
script update salt value after it process the response page so first value will
always be wrong/empty.

As script find salt value from response and update in next request, this makes 
it sequential attack, multithreaded attack with this result in failure of every
case.

