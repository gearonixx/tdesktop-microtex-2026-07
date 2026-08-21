File: Telegram/ThirdParty/MicroTeX/src/atom/atom_matrix.cpp
Function: `recalculateLine`

```diff
 } else if (h < bh) {
   const float ex = (bh - h) / skipped / 2.f;
-  const int mr = m->_i + m->_n;
-  for (int j = m->_i; j < mr; j++) {
+  const int mr = min(m->_i + m->_n, rows);
+  for (int j = max(m->_i, 0); j < mr; j++) {
     if (boxarr[j][0]->_type != AtomType::hline) {
       height[j] += ex;
       depth[j]  += ex;
     }
   }
```