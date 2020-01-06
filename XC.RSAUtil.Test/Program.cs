using System;
using System.Security.Cryptography;
using System.Text;

namespace XC.RSAUtil.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(2<<1);
			Console.WriteLine(RsaKeyGenerator.XmlKey(2048)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs1Key(2048,true)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs8Key(2048,true)[0]);


            Console.WriteLine("Key Convert:");
            var keyList = RsaKeyGenerator.Pkcs1Key(512, false);
            var privateKey = keyList[0];
            var publicKey = keyList[1];
            Console.WriteLine("public key pkcs1->xml:");
            Console.WriteLine(RsaKeyConvert.PublicKeyPemToXml(publicKey));

            var bigDataRsa=new RsaPkcs1Util(Encoding.UTF8, publicKey,privateKey,2048);
            var data = "响应式布局的概念是一个页面适配多个终端及不同分辨率。在针对特定屏幕宽度优化应用 UI 时，我们将此称为创建响应式设计。WPF设计之初响应式设计的概念并不流行，那时候大部分网页设计师都按着宽度960像素的标准设计。到了UWP诞生的时候响应式布局已经很流行了，所以UWP提供了很多响应式布局的技术，这篇文章简单总结了一些响应式布局常用的技术，更完整的内容请看文章最后给出的参考网站。所谓的传统，是指在响应式设计没流行前XAML就已经存在的应对不同分辨率的技术，毕竟桌面客户端常常也调整窗体的大小，有些人还同时使用两个不同分辨率的屏幕。以我的经验来说以下这些做法可以使UI有效应对分辨率改变不同的DPI设定、不同的本地化字符串长度都可能使整个页面布局乱掉。而且和网页不同，WPF窗体默认没有提供ScrollViewer，所以千万不能忘记。在桌面客户端合理使用以上技术可以避免客户投诉。但UWP主打跨平台，它需要更先进（或者说，更激进）的技术。微软的官方文档介绍了UWP中响应式设计常用的6个技术，包括重新定位、调整大小、重新排列、显示/隐藏、替换和重新构建，具体可见以下网站：UWP中部分控件已经实现了响应式行为， 最典型的就是NavigationView。可以使用 PaneDisplayMode 属性配置不同的导航样式或显示模式。默认情况下，PaneDisplayMode 设置为 Auto。在 Auto 模式下，导航视图会进行自适应，在窗口狭窄时为 LeftMinimal，接下来为 LeftCompact，随后在窗口变宽时为 Left。这种时候MVVM的优势就体现出来了，因为VIEW和VIEWMODEL解耦了，VIEW随便换，而且整个UI显示隐藏说不定比多个小模块独自改变性能更好。说到性能，UWP的很多场景都为已经死了多年的WindowsWobile考虑了性能，更不用说现在的桌面平台，所以做UWP不需要太过介意性能，尤其是已经在WPF上培养出小心翼翼的习惯的开发者，UWP的性能问题等真的出现了再说。除了使用显示隐藏，UWP还可以使用限定符名称指定CodeBehind对应的XAML文件，这有点像是自适应应用的话题。使用格式如下";
            var str = bigDataRsa.EncryptBigData(data, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine("Big Data Encrypt:");
            Console.WriteLine(str);
            Console.WriteLine("Big Data Decrypt:");
            Console.WriteLine(string.Join("", bigDataRsa.DecryptBigData(str,  RSAEncryptionPadding.Pkcs1)));

            Console.ReadKey();
        }
    }
}
