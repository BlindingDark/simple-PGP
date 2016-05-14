(ns gpg.core
   (:import [java.security MessageDigest]
            [java.security Key]
            [java.security KeyPairGenerator]
            [java.security KeyFactory]
            [java.security SecureRandom]
            [java.security.spec PKCS8EncodedKeySpec]
            [java.security.spec X509EncodedKeySpec]
            [java.util Arrays]
            [javax.crypto Cipher]
            [javax.crypto KeyGenerator]
            [sun.misc BASE64Encoder]
            [sun.misc BASE64Decoder])
   (:use [me.raynes.fs.compression]))

;获取hash序列
(defn md5-result
  "获取hash序列,参数为file类型,返回hash的byte数组"
  [file]
  (let [md5 (MessageDigest/getInstance "MD5")]
      (.update md5 (.getBytes (slurp file) "utf-8"))
      (.digest md5)))

;BASE64编码
(defn BASE64-encoder 
  "参数是要编码的byte数组,返回String"
  [file-byte]
  (.encodeBuffer (BASE64Encoder.) file-byte))

;BASE64解码
(defn BASE64-decoder
  "参数是要解码的file-string,返回解码后的byte"
  [file-string]
  (.decodeBuffer (BASE64Decoder.) file-string))

;创建hash文件
(defn creat-hash-file
  "第一个参数是待取得摘要的file,第二个参数是输出的hash-file(BASE64编码)"
  [f-mail f-hash]
  (copy (BASE64-encoder (md5-result f-mail)) f-hash))


(defn zip-2-files 
  "压缩两个文件,第一个参数是输出zip-file,后两个参数是要压缩的file"
  [out-file in-1 in-2]
  (zip (.getPath out-file) [[(.getName in-1) (slurp in-1)] [(.getName in-2) (slurp in-2)]]))


;生成公钥和私钥对，基于RSA算法
(defn generate-RSA-key-pair
  "生成公钥和私钥对，RSA算法,无参数,返回公钥-私钥对"
  []
  (let [key-pair-gen  (KeyPairGenerator/getInstance "RSA")]
    (.initialize key-pair-gen 1024)
    (let [key-pair (.generateKeyPair key-pair-gen)]
      (.getPublic key-pair)
      (map #(BASE64-encoder (.getEncoded %)) [(.getPublic key-pair) (.getPrivate key-pair)]))))

(defn get-private-key-ob
  "得到private-key的对象,参数是私钥字符串"
  [private-key]
  (let [keyFactory  (KeyFactory/getInstance "RSA")]
    (.generatePrivate keyFactory (PKCS8EncodedKeySpec. (BASE64-decoder private-key)))))

(defn get-public-key-ob
  "得到public-key的对象,参数是公钥字符串"
  [public-key]
  (let [keyFactory  (KeyFactory/getInstance "RSA")]
    (.generatePublic keyFactory (X509EncodedKeySpec. (BASE64-decoder public-key)))))

;生成指定DES密钥key对象
(defn generate-DES-key
  "参数为密钥字符串,返回值为DES密钥key对象"
  [string-key]
  (let [key-gen  (KeyGenerator/getInstance "DESede")]
    (.init key-gen (SecureRandom. (.getBytes string-key)))
    (.generateKey key-gen)))


;生成随机DES密钥key对象和密钥
(defn generate-random-DES-key
  "返回值为string-key keyObject"
  []
  (let [string-key (str (rand))]
    [string-key (generate-DES-key string-key)]))


(defn save-key-pair
  "把得到的list保存成一组key.txt,第一个参数是key-pair,第二个参数是输出路径"
  [key-pair-list file-path]
  (spit (str file-path "/public.txt") (first key-pair-list))
  (spit (str file-path "/private.txt") (second key-pair-list)))

(defn load-key-pair
  "读取硬盘上的key-pair,参数是文件所在路径"
  [file-path]
  (list (slurp (str file-path "/public.txt")) (slurp (str file-path "/private.txt"))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn encrypt
  "加密byte数组,第一个参数是算法名字符表示,第二个参数是key,第三个参数是要加密的byte数组"
  [algorithm  some-key some-byte]
  (let [cipher (Cipher/getInstance algorithm)]
     (.init cipher Cipher/ENCRYPT_MODE some-key)
     (.doFinal cipher some-byte)))

(defn decrypt
  "解密byte数组,第一个参数是算法名字符表示,第二个参数是key,第三个参数是要解密的byte数组"
  [algorithm  some-key some-byte]
  (let [cipher (Cipher/getInstance algorithm)]
     (.init cipher Cipher/DECRYPT_MODE some-key)
     (.doFinal cipher some-byte)))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn DES-encrypt
  "加密byte数组,第一个参数是key,第二个参数是要加密的byte数组"
   [some-key some-byte]
   (encrypt "DESede" some-key some-byte))

(defn DES-decrypt
   "解密byte数组,第一个参数是key,第二个参数是要解密的byte数组"
   [some-key some-byte]
   (decrypt "DESede" some-key some-byte))


(defn RSA-encrypt
   "加密byte数组,第一个参数是key,第二个参数是要加密的byte数组"
   [some-key some-byte]
   (encrypt "RSA" some-key some-byte))

(defn RSA-decrypt
   "解密byte数组,第一个参数是key,第二个参数是要解密的byte数组"
   [some-key some-byte]
   (decrypt "RSA" some-key some-byte))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn decrypt-string
  "解密,第一个参数是解密方法,第二个参数是key-ob,第三个参数是解密的String,返回String"
  [decrypt-fun key-ob some-string]
  (String. (decrypt-fun key-ob (BASE64-decoder some-string))))

(defn encrypt-string
  "加密,第一个参数是加密方法,第二个参数是key-ob,第三个参数是加密的String,返回String"
  [encrypt-fun key-ob some-string]
  (BASE64-encoder (encrypt-fun key-ob (.getBytes some-string))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn DES-decrypt-string
  "DES解密,第一个参数是key-ob,第二个参数是解密的String,返回String"
  [key-ob some-string]
    (decrypt-string DES-decrypt key-ob some-string))

(defn DES-encrypt-string
  "DES加密,第一个参数是key-ob,第二个参数是加密的String,返回String"
  [key-ob some-string]
    (encrypt-string DES-encrypt key-ob some-string))





(defn RSA-decrypt-string
  "第一个参数是key-ob
        第二个参数是要解密的String
        返回解密后的String"
  [key-ob some-string]
    (decrypt-string RSA-decrypt key-ob some-string))

(defn RSA-encrypt-string
  "第一个参数是key-ob
        第二个参数是要加密的String
        返回解密后的String"
  [key-ob some-string]
    (encrypt-string RSA-encrypt key-ob some-string))


(defn RSA-encrypt-by-private-key;这里是函数名
  "读取private-key来加密指定的String
      第一个参数是私钥String
      第二个参数是要加密的String";这里写API文档
  [private-key some-string];分号是注释的符号。
  (RSA-encrypt-string (get-private-key-ob private-key) some-string));函数主体

(defn RSA-encrypt-by-public-key;这里是函数名
  "读取private-key来加密指定的String
      第一个参数是公钥String
      第二个参数是要加密的String";这里写API文档
  [public-key some-string];分号是注释的符号。
  (RSA-encrypt-string (get-public-key-ob public-key) some-string));函数主体


(defn RSA-decrypt-by-private-key
  "第一个参数是私钥String,第二个参数是要解密的String"
  [private-key some-string]
  (RSA-decrypt-string (get-private-key-ob private-key) some-string))

(defn RSA-decrypt-by-public-key
  "第一个参数是公钥String,第二个参数是要解密的String"
  [public-key some-string]
  (RSA-decrypt-string (get-public-key-ob public-key) some-string))


