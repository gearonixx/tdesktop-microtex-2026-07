```diff
diff --git a/src/atom/atom_space.h b/src/atom/atom_space.h
--- a/src/atom/atom_space.h
+++ b/src/atom/atom_space.h
@@
   /** Get the scale factor from the given unit and environment */
   inline static float getFactor(UnitType unit, const Environment& env) {
-    return _unitConversions[static_cast<i8>(unit)](env);
+    const auto i = static_cast<i8>(unit);
+    constexpr i32 kUnitConversionCount =
+        sizeof(_unitConversions) / sizeof(_unitConversions[0]);
+    if (i < 0 || i >= kUnitConversionCount)
+      return 0.f;
+    return _unitConversions[i](env);
   }

   inline static float getSize(UnitType unit, float size, const Environment& env) {
-    return _unitConversions[static_cast<i8>(unit)](env) * size;
+    const auto i = static_cast<i8>(unit);
+    constexpr i32 kUnitConversionCount =
+        sizeof(_unitConversions) / sizeof(_unitConversions[0]);
+    if (i < 0 || i >= kUnitConversionCount)
+      return 0.f;
+    return _unitConversions[i](env) * size;
   }
```