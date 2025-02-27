# PyClassInformer #
#### Yet Another RTTI Parsing IDA plugin ####
![PyClassInformer Icon](/pyclassinformer/pci_icon.png)

PyClassInformer is an RTTI parser. Although there are several RTTI parsers such as Class Informer and SusanRTTI, and even IDA can also parse RTTI, I created this tool. It is because they cannot be used as libraries for parsing RTTI. IDA cannot show class hierarchies, either.

PyClassInformer can parse RTTI for Windows on x86 and x64. Since it is written in pure python, you can run it on IDA for Mac OS and Linux as well as Windows. You can also use results of parsing RTTI in your python code by importing this tool as a library.

### Usage ###
Launch it by pressing Alt+Shift+L. Or navigate to Edit -> Plugins -> PyClassInformer.

### Installation ###
Put "pyclassinformer_plugin.py" and "pyclassinformer" folder including the files under it into the "plugins" folder of IDA's user directory ($IDAUSR).

See the URL if you don't know about "$IDAUSR".  
[https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/)  
[https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml](https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml)

### Requirements ###
- IDA Pro 7.4 or later (I tested on 7.4 SP1, 7.5 SP3, 8.0 and 9.0 SP1)
- Python 3.x (I tested on Python 3.8 and 3.10)

You will need at least IDA Pro 7.4 or later because of the APIs that I use.

### Example Results ###
![PyClassInformer Result](/images/result.png)
The figure above is an example of PyClassInformer result. And the figure below is an example of the original Class Informer result.  
As you see, almost all columns are matched with the original ones.   
  
In addition, PyClassInformer has two more columns. One is "offset", which shows the offset of a vftable in a class layout.  
  
Another one named "Hierarchy Order" shows class hierarchy information related to a vftable of a line. The column shows the order of  inheritance from the class to the top-most super class.  
  
These are useful for grasping class layouts and class hierarchies. Double-clicking a line navigates to its vftable address as weiil.

![Original ClassInformer Result](/images/orig_class_informer.png)
If you check the Output subview, you will also see parsed RTTI information such as Complete Object Locator as COL, Class Hierarchy Descriptor as CHD and Base Class Descriptor as BCD with their addresses. They are useful for checking more details and debugging.

![Class Hierarchy](/images/class_hierarchy.png)  
You will also see class hierarchies by checking indents of BCDs. For example, CMFCComObject, which is the class for the vftable at 0x530fcc, inherits ATL::CAccessibleProxy. And ATL::CAccessibleProxy inherits three super classes, ATL::CComObjectRootEx, ATL::IAccessibleProxyImpl and IOleWindow. Like this, you can get class hierarchy information as a form of a tree.

### Note ###
- I **WILL NOT** support parsing GCC's RTTI. **DO NOT** open an issue about it.
- I **WILL NOT** support beta versions of IDA. **DO NOT** open an issue about it.
- Some code is from SusanRTTI and the output table is similar to Class Informer.  
[https://github.com/nccgroup/SusanRTTI](https://github.com/nccgroup/SusanRTTI)  
[https://sourceforge.net/projects/classinformer/](https://sourceforge.net/projects/classinformer/)
