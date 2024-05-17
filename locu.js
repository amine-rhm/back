const express=require("express");
const app=express();
const util = require('util');
const bodyParser =require( "body-parser");
const { v4: uuidv4 } = require('uuid');
const { generateJwt } = require("./jwt/genratetoken");
const cors =require("cors");
const mysql = require('mysql');
const fs =require("fs");
const bcrypt=require("bcryptjs")
require('dotenv').config();
const jwt =require("jsonwebtoken");
const { upload } = require('./middleware/fich');
const path =require( "path");
const cookieParser =require("cookie-parser");
const helmet =require("helmet");
app.use(express.static('public'));
app.use(cookieParser());
app.use(helmet());
const nodemailer = require('nodemailer');
const auth = require("./middleware/auth");
const { error, Console } = require("console");
const { userInfo } = require("os");
const pool = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "locu"
});

app.use(express.json()) ;
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(cookieParser());
app.use(express.json()); // req.body
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  helmet({
    frameguard: {
      action: "deny",
    },
    xssFilter: true,
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);


// Connexion à la base de données
pool.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données:', err);
  } else {
    console.log('Connexion à la base de données établie avec succès.');
  }
});

const saltOrRounds = 10;
app.post("/api/v1/register", (req, res) => {
  try {
    const nom = req.body.nom;
    const prenom = req.body.prenom;
    const email = req.body.email;
    const num = req.body.num;
    const password = req.body.password;

    // Vérification si l'email est déjà utilisé
    pool.query(
      "SELECT * FROM client WHERE email = ?",
      [email],
      (err, result) => {
        if (err) {
          console.error("Erreur lors de la vérification de l'email:", err);
          return res.status(500).json({ error: "Erreur interne du serveur" });
        }
        if (result && result.length > 0) {
          return res.status(400).json({ error: "L'email est déjà utilisé!" });
        }

        // Génération du nom d'utilisateur
        let username = "";
        if (nom && prenom) {
          username = `${nom.toLowerCase()}_${prenom.toLowerCase()}`;
        } else {
          console.error("Erreur : nom ou prénom non défini");
          return res.status(400).json({ error: "Nom ou prénom non défini" });
        }

        // Hachage du mot de passe de l'utilisateur
        bcrypt.hash(password, saltOrRounds, (err, hash) => {
          if (err) {
            console.error("Erreur de hachage :", err);
            return res.status(500).json({ error: "Erreur dans le hachage" });
          }

          const userId = uuidv4();
          const accountId = uuidv4();

          // Ajout des données dans la table client
          pool.query(
            "INSERT INTO client (iduser, nom, prenom, num, email) VALUES (?, ?, ?, ?, ?)",
            [userId, nom, prenom, num, email],
            (err, result) => {
              if (err) {
                console.error("Erreur d'insertion dans la table client:", err);
                return res.status(500).json({ error: "Erreur d'insertion dans la table client" });
              }
              // Ajout des données dans la table compte
              pool.query(
                "INSERT INTO compte (idcom, username, passeword, iduser) VALUES (?, ?, ?, ?)",
                [accountId, username, hash, userId],
                (err, result) => {
                  if (err) {
                    console.error("Erreur d'insertion dans la table compte:", err);
                    return res.status(500).json({ error: "Erreur d'insertion dans la table compte" });
                  }
                  
                  const token = generateJwt({ userId, email, nom, prenom, hash });
                  res.json({ token: `Bearer ${token}` });
                }
              );
            }
          );
        });
      }
    );
  } catch (error) {
    console.error("Erreur lors de l'enregistrement de l'utilisateur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});


app.post("/api/v1/login",(req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  pool.query(
    'SELECT c.iduser, c.nom, c.prenom, c.role, co.passeword FROM client c INNER JOIN compte co ON c.iduser = co.iduser WHERE c.email = ?',
    [email],
    (err, result) => {
      if (err) {
        console.error("Erreur lors de la recherche de l'utilisateur:", err);
        return res.status(500).json({ error: "Erreur interne du serveur" });
      } else if (result.length > 0) {
        const user = result[0];
        const hashedPassword = user.passeword;
        bcrypt.compare(password, hashedPassword, (error, response) => {
          if (response) {
            const { iduser, nom, prenom, role } = user;
            const token = generateJwt({ userId: iduser, nom, prenom, email, role });
            res.json({ token: `Bearer ${token}`, role });
          } else {
            res.status(401).json({ error: "Mot de passe incorrect" });
          }
        });
      } else {
        res.status(404).json({ error: "Utilisateur non trouvé" });
      }
    }
  );
});



//  Logout
app.get("/api/v1/logout", (req, res) => {
  try {

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer")) {
      const token = authHeader.split(" ")[1];
      return res.json({ authenticated: false, message: "Déconnexion réussie." });
    } else {

      return res.status(401).json({ message: "Aucun jeton d'authentification fourni." });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la déconnexion", error: error.message });
  }
});




//prover the auth
/*
app.get("/api/v1/verif", auth, async (req, res) => {
  try {
    const userId = req.userData.userId;
    const user = await pool.query("SELECT * FROM client WHERE iduser = ?", [userId]);
    if (!user || user.length === 0) {
      return res.json({ message: "Utilisateur non trouvé dans la base de données" });
    }
    res.json({ message: "Token valide" });
    console.log(userId); 
  } catch (error) {
    console.error("Erreur lors de la vérification du token avec l'ID de l'utilisateur:", error);
    res.json({ message: "Erreur serveur lors de la vérification du token avec l'ID de l'utilisateur", error: error.message });
  }
});

*/

app.get("/api/v1/verif", auth, async (req, res) => {
  try {
    const userId = req.userData.userId;
    const nom = req.userData.nom;
    const prenom=req.userData.prenom;
    const email=req.userData.email;
    const user = await pool.query("SELECT * FROM client WHERE iduser = ? ", [userId]);
    if (!user || user.length === 0) {
      return res.json({ message: "Utilisateur non trouvé dans la base de données" });
    }
    
    res.json({ message: "Token valide", bienvenue: ` nom:${nom} prenom: ${prenom} email: ${email}` });

    console.log(userId);
    console.log(`kshi dizem a: ${nom} ${prenom}`);

  } catch (error) {
    console.error("Erreur lors de la vérification du token avec l'ID de l'utilisateur:", error);
    res.json({ message: "Erreur serveur lors de la vérification du token avec l'ID de l'utilisateur", error: error.message });
  }
});



// Verify the current user token if authenticated
app.get("/api/v1/that", auth, async (request, response) => {
  try {
    response.json(true);
  } catch (error) {
    console.error(error.message);
    response.send({ msg: "Unauthenticated" });
  }
});


// gerer le compte 
app.put('/api/v1/gere/compte', auth, async (req, res) => {
  try {
    const userId = req.userData.userId;
    const { nom, prenom,num,email } = req.body;

    const username = nom.toLowerCase() + "_" + prenom.toLowerCase();
    console.log(userId);
    // Mettre à jour les informations dans la table client
    pool.query(
      'UPDATE client SET prenom=?, nom=?, email=?,num=? WHERE iduser=?',
      [ nom,prenom, email,num, userId],
      (error, result) => {
        if (error) {
          console.error("Erreur lors de la mise à jour des informations dans la table client:", error);
          res.json({ error: "Erreur interne du serveur" });
        } else {
          // Mettre à jour le mot de passe dans la table compte
          pool.query(
            'UPDATE compte SET username=? WHERE iduser=?',
            [username, userId],
            (error, results) => {
              if (error) {
                console.log(userId);
                console.error("Erreur lors de la mise à jour du mot de passe dans la table compte:", error);
                res.json({ error: "Erreur interne du serveur" });
              } else {
                // Envoyer une réponse de succès si les mises à jour sont effectuées avec succès
                res.json({ message: "Mise à jour réussie" });
              }
            }
          );
        }
      }
    );
  } catch (error) {
    console.error("Erreur lors de la mise à jour des informations:", error);
    res.json({ error: "Erreur interne du serveur" });
  }
});


// delete compte 
app.delete('/api/v1/gere/compte', auth, async (req, res) => {
  try {
    const userId = req.userData.userId;

    // Supprimer l'utilisateur des tables 'client' et 'compte'
    pool.query('DELETE FROM client WHERE iduser = ?', [userId], (error, result) => {
      if (error) {
        console.error("Erreur lors de la suppression de l'utilisateur dans la table client:", error);
        res.json({ error: "Erreur interne du serveur" });
      } else {
        pool.query('DELETE FROM compte WHERE iduser = ?', [userId], (error, results) => {
          if (error) {
            console.error("Erreur lors de la suppression de l'utilisateur dans la table compte:", error);
            res.json({ error: "Erreur interne du serveur" });
          } else {
            res.json({ message: "Compte supprimé avec succès" });
          }
        });
      }
    });
  } catch (error) {
    console.error("Erreur lors de la suppression de l'utilisateur:", error);
    res.json({ error: "Erreur interne du serveur" });
  }
});



// Route d'inscription de l'administratr
app.post("/api/v1/admin/register", async (req, res) => {
  try {
    const  admin = req.body.admin;
    const  password  = req.body.password;

    // Hachage du mot de passe de l'administrateur
    const hash = await bcrypt.hash(password, saltOrRounds);
    console.log(hash)

    const adminid = uuidv4();

    // Ajout des données dans la table admin
    await pool.query(
      "INSERT INTO admine (adminid, admin, passeword) VALUES (?, ?, ?)",
      [adminid, admin, hash]
    );

    // Génération du jeton JWT
    const token = generateJwt({ adminid, admin, hash });
    
    res.json({ token: `Bearer ${token}` });
  } catch (error) {
    console.error("Erreur lors de l'enregistrement de l'administrateur:", error);
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

app.post("/api/v1/admin/login", (req, res) => {
  const  admin = req.body.admin;
  const password= req.body.password
  
  pool.query(
    'SELECT * FROM admine WHERE admin = ?',
    [admin],
 
    (err, result) => {
      if (err) {
        console.error("Erreur lors de la recherche de l'administrateur:", err);
        res.status(500).json({ error: "Erreur interne du serveur" });
      } else if (result.length > 0) {
        const hashed = result[0].passeword;
        console.log(hashed),
        bcrypt.compare(password, hashed, (error, response) => {

          if (response) {

            const token = generateJwt({ admin });
            res.json({ token: `Bearer ${token}` });

          } else {
            res.status(401).json({ error: "Mot de passe incorrect" });
          }
        });
      } else {
        res.status(404).json({ error: "Utilisateur non trouvé" });
      }

    }
  );
});






// déposer une annonce 
app.post('/api/v1/new/annonce',auth, upload.array('file', 5), async (req, res) => {
  const userId = req.userData.userId;
  try {
    if (!req.files || req.files.length === 0) {
      return res.send({ message: "Aucun fichier n'a été téléchargé." });
    }
    const image1 = req.files[0].filename;  
    const image2 = req.files[1] ? req.files[1].filename : null;
    const image3 = req.files[2] ? req.files[2].filename : null;
    const image4 = req.files[3] ? req.files[3].filename : null;
    const image5 = req.files[4] ? req.files[4].filename : null;
   
    const dateAjout = new Date();
    const { type, surface, adresse, prix, titre, description, meuble, equipement, ville, capacite, puissance, materiel, taille ,etage,categorie, largeur, longueur,type_residence,etage_maison,etage_villa, type_villa, type_appartement,Ascenseur, Wifi,Camera ,Parking ,Garage,Electroménager,Climatiseur,Citerne,go,camera_surveillance,Espace_Sup} = req.body;

    if (!titre || !description || !prix || !description || !adresse) {
      return res.send({ message: "Ces champs sont requis."});
    }

    const idann = uuidv4();
    await pool.query(
      "INSERT INTO annonce (idann, titre, description, date_ajout, image1, image2, image3,image4,image5,iduser) VALUES (?, ?, ?,?, ?, ?, ?, ?,?,?)",
      [idann, titre, description,dateAjout,image1, image2, image3,image4,image5,userId]
    );
    console.log("bien inserrer dans la table annonce")
    // Insérer dans la table Bien si nécessaire
    const idB = uuidv4();
    await pool.query(
      "INSERT INTO bien (idB,type,surface,prix,ville,adresse,userId,idann) VALUES (?,?, ?, ?, ?, ?, ?,?)",
      [idB, type,surface, prix,ville,adresse,userId, idann]
    );
    console.log("bien inserrer dans la table bien",idB)

    let idres; 
    if (type === "Résidentiel") {
        idres = uuidv4(); 
        await pool.query(
            "INSERT INTO résidentiel (idres ,equipement, meuble,type_residence, idb, Ascenseur, Wifi ,Parking ,Garage,Electroménager,Camera,Climatiseur,Citerne,go) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [idres ,equipement, meuble,type_residence,idB, Ascenseur, Wifi ,Parking ,Garage,Electroménager,Camera,Climatiseur,Citerne,go]
        );

        console.log("Bien inséré dans la table résidentiel", idres); 
    
        if (type_residence === "Maison") {
            idMais = uuidv4(); 
            await pool.query(
                "INSERT INTO maison (idMais, etage_maison,idres) VALUES (?, ?, ?)",
                [idMais, etage_maison, idres]
            );
            console.log("Bien inséré dans la table maison", idMais, idres); 
        } else if (type_residence === "Villa") {
            idVil = uuidv4(); 
            await pool.query(
                "INSERT INTO villa (idVil, etage_villa, type_villa, idres) VALUES (?, ?, ?, ?)",
                [idVil, etage_villa, type_villa, idres]
            );
            console.log("Bien inséré dans la table villa", idVil, idres); 
        } else if (type_residence === "Studio") {
            idStu = uuidv4(); 
            await pool.query(
                "INSERT INTO studio (idStu, idres) VALUES (?, ?)",
                [idStu, idres]
            );
            console.log("Bien inséré dans la table studio", idStu, idres); 
        } else if (type_residence === "Appartement") {
            idApp = uuidv4(); 
            await pool.query(
                "INSERT INTO appartement (idApp, type_appartement, idres) VALUES (?, ?, ?)",
                [idApp, type_appartement, idres]
            );
            console.log("Bien inséré dans la table appartement", idApp, idres); 
        }
    }
    let idIndu; 
    if (type === "Industriel") {
       idIndu = uuidv4();
      await pool.query(
          "INSERT INTO industriel (idIndu, capacite, puissance, materiel, taille,idb) VALUES (?, ?, ?, ?, ?, ?)",
          [idIndu, capacite, puissance,materiel, taille,idB]
      );
      console.log("bien inserrer dans la table Industriel", idIndu,idB);
  }

   
    let idComm; 
    if (type === "Commercial") {
      idComm = uuidv4();
      await pool.query(
          "INSERT INTO commercial (idComm,camera_surveillance,Garage,Espace_Sup, etage,idb) VALUES (?, ?, ?, ?,?,?)",
          [idComm,camera_surveillance,Garage,Espace_Sup, etage,idB]
      );
      console.log("bien insérer dans la table Commercial", idComm);
  }
  let idTerr; 
  if (type === "Terrain") {
    idTerr = uuidv4();
    await pool.query(
        "INSERT INTO terrain (idTerr, categorie, largeur, longueur,idb) VALUES (?, ?, ?, ?, ?)",
        [idTerr, categorie, largeur, longueur,idB]
    );
    console.log("bien insérer dans la table Terrain", idTerr,idB);
  }
    // Retour d'informations supplémentaires
    res.send({ message: "Annonce ajoutée avec succès.", idann});
  } catch (error) {
    console.error("Erreur lors de l'ajout de l'annonce :", error);
    res.send({ message: "Une erreur s'est produite lors de l'ajout de l'annonce." });
  }
});


// modifier une annonce
app.put("/api/v1/modifie/annonce/:id", auth, async (req, res) => {
  try {
    const id = req.params.id;
    const userId = req.userData.userId;
    const { titre, description, date_ajout } = req.body;
    await pool.query(
    "UPDATE annonce SET titre = ?, description = ?, date_ajout = ?, iduser = ? WHERE idann = ?",
      [titre, description, date_ajout, userId, id],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        res.json({ message: "Annonce modifiée avec succès." });
      }

    );
  } catch (error) {
    console.log(error);
    res.json({ error: "Une erreur s'est produite lors de la modification de l'annonce." });
  }
});


// supprimer une annonce 

app.delete("/api/v1/delete/annonce/:id", auth, async (req, res) => {
  try {
    const id1 = req.params.id;
    const userId = req.userData.userId;

    console.log(`Attempting to delete annonce with id: ${id1} for user: ${userId}`);

    const query = util.promisify(pool.query).bind(pool);
    // Suppr des liens entre l'annonce et les enregistrements dans la table "bien"
    await query("UPDATE bien SET idann = NULL WHERE idann = ?", [id1]);
    // Suppr de l'annonce de la table "annonce"
    const result = await query("DELETE FROM annonce WHERE idann = ? AND iduser = ?", [id1, userId]);
    console.log('Result of DELETE query:', result);
    if (result.affectedRows === 0) {
      console.log("No rows affected, user not authorized or annonce does not exist.");
      return res.json({ error: "You are not authorized to delete this listing or the listing does not exist." });
    }

    // Récupération des images supprimées (si nécessaire)
    const deletedImages = {
      image1: result.image1,
      image2: result.image2,
      image3: result.image3,
      image4: result.image4,
      image5: result.image5
    };
    const responseJSON = {
      message: "Annonce deleted, klsh bien dghhn",
      deletedImages: deletedImages
    };
    res.json(responseJSON);

  } catch (error) {
    console.error(error);
    res.json({ error: "Internal Server Error" });
  }
});






// recuperere tous les annonces 
app.get("/api/v1/all/annonce", (req, res) => {
  try {
    pool.query(
      "SELECT idann, titre, description, date_ajout, image1, image2, image3, image4, image5, iduser FROM annonce ORDER BY idann",
      (error, result) => {
        if (error) {
      return res.status(500).json({ message: "Erreur lors de la récupération des annonces." });
        }
        console.log("A ce niveau, il n'y a pas d'erreur");
        res.json({
          totalListing:result.length,
          listing: result
        });
      }
    );
  } catch (error) {
    console.error(error);
  }
});


// recuperer une annonce avec sans id join la tbale bien et clien 

app.get("/api/v1/single/annonces/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
     " SELECT annonce.idann, annonce.titre, annonce.description, annonce.date_ajout, annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5, annonce.iduser, client.nom, client.prenom,client.num, client.email, bien.idB, bien.type AS bien_type, bien.surface AS bien_surface, bien.prix AS bien_prix,bien.ville AS bien_ville,bien.adresse AS bien_adresse, bien.userId AS bien_userId, bien.idann AS bien_idann FROM annonce INNER JOIN client ON annonce.iduser = client.iduser INNER JOIN bien ON annonce.idann = bien.idann WHERE annonce.idann = ?",

      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        response.json(result[0]);
      }
    );
  } catch (error) {
    console.error(error);
    response.status(500).json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});

// recuperer une annonce avec id specifique et on inclu les info de le client 
app.get("/api/v1/single/whithinfoclient/annonces/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      "SELECT annonce.idann, annonce.titre, annonce.description, annonce.date_ajout, annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5, annonce.iduser, client.nom, client.prenom,client.num, client.email FROM annonce INNER JOIN client ON annonce.iduser = client.iduser WHERE annonce.idann = ?",
      [annid],
      (err, result) => {
        
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }

        
        response.json(result[0]);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});


// Définition de la fonction removeNullValues à l'extérieur de la route
function removeNullValues(obj) {
  const newObj = {};
  for (const key in obj) {
    if (obj[key] !== null) {
      newObj[key] = obj[key];
    }
  }
  return newObj;
}

// recuperer jusqua le type de bien 
app.get("/api/v1/info/annonce/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      ` SELECT  CONCAT(',', 
        CASE 
          WHEN bien.type = 'Terrain' THEN CONCAT(terrain.categorie, ',', terrain.largeur, ',', terrain.longueur,',', terrain.meuble) 
          WHEN bien.type = 'Industriel' THEN CONCAT( industriel.puissance, ',', industriel.puissance, ',', industriel.materiel, ',', industriel.taille, ',', industriel.meuble) 
          WHEN bien.type = 'Résidentiel' THEN CONCAT(résidentiel.meuble, ',', résidentiel.equipement, ',', résidentiel.type_residence) 
        WHEN bien.type = 'Commercial' THEN CONCAT(commercial.etage, ',', commercial.camera_surveillance, ',',commercial.Garage, ',', commercial.Espace_Sup) 
          ELSE '' 
        END) AS selected_data, 
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.ville,
        bien.adresse,
        bien.userId, 
        bien.idann,
        résidentiel.meuble AS résidentiel_meuble,
        résidentiel.equipement AS résidentiel_equipement,
        résidentiel.type_residence AS résidentiel_residence,
        commercial.etage AS commercial_etage,
        commercial.camera_surveillance AS commercial_camera,
        commercial.Garage AS commercial_Garage,
        commercial.Espace_Sup AS commercial_Espace,
        commercial.meuble AS commercial_meuble,
        industriel.capacite AS industriel_capacite,
        industriel.puissance AS industriel_puissance,
        industriel.materiel AS industriel_materiel,
        industriel.taille  AS industriel_taille,
        industriel.meuble AS industriel_meuble,
        terrain.categorie AS terrain_categorie,
        terrain.largeur AS terrain_largeur,
        terrain.longueur AS terrain_longueur,
        terrain.meuble AS terrain_meuble


      FROM bien 
      INNER JOIN annonce ON bien.idann = annonce.idann 
      LEFT JOIN terrain ON bien.idB = terrain.idb 
      LEFT JOIN industriel ON bien.idB = industriel.idb 
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb 
      LEFT JOIN commercial ON bien.idB = commercial.idb 
      WHERE annonce.idann = ?`,
      [annid],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        // Renvoyer les données
        const formattedData = {
          titre: result[0].titre,
          description: result[0].description,
          date_ajout: result[0].date_ajout,
          images: [
            result[0].image1,
            result[0].image2,
            result[0].image3,
            result[0].image4,
            result[0].image5
          ].filter(Boolean),
          iduser: result[0].iduser,
          idB: result[0].idB,
          type: result[0].type,
          surface: result[0].surface,
          prix: result[0].prix,
          ville:result[0].ville,
          adresse:result[0].adresse,
          userId: result[0].userId,
          idann: result[0].idann,
          bien_details: {}
        };
        

        if (result[0].type === 'Terrain') {
          formattedData.bien_details.terrain = removeNullValues({
            categorie: result[0].terrain_categorie,
            largeur: result[0].terrain_largeur,
            longueur: result[0].terrain_longueur,
            meuble: result[0].terrain_meuble,
          });
        } else if (result[0].type === 'Industriel') {
          formattedData.bien_details.industriel = removeNullValues({
            capacite:result[0].industriel_capacite,
            puissance: result[0].industriel_puissance,
            materiel: result[0].industriel_materiel,
            taille: result[0].industriel_taille,
            meuble: result[0].industriel_meuble,
          });
        } else if (result[0].type === 'Résidentiel') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            equipement: result[0].résidentiel_equipement,
            type_residence: result[0].résidentiel_residence

          });
        } else if (result[0].type === 'Commercial') {
          formattedData.bien_details.commercial = removeNullValues({
            etage: result[0].commercial_etage,
            camera_surveillance: result[0].commercial_camera,
            Garage:result[0].commercial_Garage,
            Espace_Sup:result[0].commercial_Espace,
            meuble: result[0].commercial_meuble

          });
        }
        
        response.json(formattedData);

        
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});


// recuperer jusq le type de resedese (mais,app,st,villa) ---- tyi mzl tina ville et adresse g bien
app.get("/api/v1/info/pro/annonce/:id", async (request, response) => {
  try {
    const annid = request.params.id;
    await pool.query(
      ` SELECT CONCAT(',',
      CASE
      WHEN bien.type = 'Terrain' THEN CONCAT(terrain.categorie, ',', terrain.largeur, ',', terrain.longueur)
      WHEN bien.type = 'Industriel' THEN CONCAT(industriel.puissance, ',', industriel.materiel, ',', industriel.taille)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN CONCAT(maison.etage_maison, ',', résidentiel.meuble, ',', résidentiel.equipement, ',', résidentiel.type_residence, ',', résidentiel.Ascenseur, ',', résidentiel.Wifi, ',',résidentiel.Camera, ',',résidentiel.Parking, ',', résidentiel.Garage, ',', résidentiel.Electroménager	, ',', résidentiel.Climatiseur, ',',  résidentiel.Citerne)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN CONCAT(villa.etage_villa, ',', villa.type_villa, ',', résidentiel.meuble, ',', résidentiel.equipement,',', résidentiel.type_residence)
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN CONCAT(studio.idStu, ',', résidentiel.meuble, ',',  résidentiel.equipement, ',', résidentiel.type_residence)    
      WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN CONCAT(appartement.type_appartement, ',', résidentiel.meuble, ',', résidentiel.equipement, ',',  résidentiel.type_residence)    
      WHEN bien.type = 'Commercial' THEN CONCAT(commercial.etage, ',', commercial.camera_surveillance, ',',commercial.Garage, ',', commercial.Espace_Sup)
        ELSE ''
      END) AS selected_data,
      annonce.titre, 
      annonce.description, 
      annonce.date_ajout, 
      annonce.image1, 
      annonce.image2, 
      annonce.image3, 
      annonce.image4, 
      annonce.image5, 
      annonce.iduser, 
      bien.idB, 
      bien.type, 
      bien.surface, 
      bien.prix, 
      bien.userId, 
      bien.idann,
      bien.ville,
      bien.adresse,
      client.nom,
      client.prenom,
      client.num,
      client.email,
      résidentiel.meuble AS résidentiel_meuble,
      résidentiel.equipement AS résidentiel_equipement,
      résidentiel.type_residence AS résidentiel_residence,
      résidentiel.Ascenseur AS résidentiel_Ascenseur,
      résidentiel.Wifi AS résidentiel_Wifi,
      résidentiel.Camera AS résidentiel_Camera,
      résidentiel.Parking AS  résidentiel_Parking,
      résidentiel.Garage  AS  résidentiel_Garage,
      résidentiel.Electroménager  AS résidentiel_Elec,
      résidentiel.Climatiseur  AS résidentiel_Clim,
      résidentiel.Citerne AS résidentiel_Citerne ,
      commercial.etage AS commercial_etage,
      commercial.camera_surveillance AS commercial_camera,
      commercial.Garage AS commercial_Garage,
      commercial.Espace_Sup AS commercial_Espace,
      commercial.meuble AS commercial_meuble,
      industriel.capacite AS industriel_capacite,
      industriel.puissance AS industriel_puissance,
      industriel.materiel AS industriel_materiel,
      industriel.taille  AS industriel_taille,
      industriel.meuble AS industriel_meuble,
      terrain.categorie AS terrain_categorie,
      terrain.largeur AS terrain_largeur,
      terrain.longueur AS terrain_longueur,
      terrain.meuble AS terrain_meuble,
      maison.etage_maison AS maison_etage,
      villa.etage_villa AS villa_etage,
      villa.type_villa AS villa_type,
      appartement.type_appartement AS appartement_type
    FROM bien
    INNER JOIN annonce ON bien.idann = annonce.idann
    left join client on client.iduser = annonce.iduser
    LEFT JOIN terrain ON bien.idB = terrain.idb
    LEFT JOIN industriel ON bien.idB = industriel.idb
    LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
    LEFT JOIN commercial ON bien.idB = commercial.idb
    LEFT JOIN maison ON maison.idres = résidentiel.idres
    LEFT JOIN villa ON villa.idres = résidentiel.idres
    LEFT JOIN studio ON studio.idres = résidentiel.idres
    LEFT JOIN appartement ON appartement.idres = résidentiel.idres
    WHERE annonce.idann = ? `,
      [annid],
      (err, result) => {
        
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        // Renvoyer les données
        const formattedData = {
          titre: result[0].titre,
          description: result[0].description,
          date_ajout: result[0].date_ajout,
          images: [
            result[0].image1,
            result[0].image2,
            result[0].image3,
            result[0].image4,
            result[0].image5
          ].filter(Boolean),
          idB: result[0].idB,
          type: result[0].type,
          surface: result[0].surface,
          prix: result[0].prix,
          userId: result[0].userId,
          idann: result[0].idann,
          adresse: result[0].adresse,
          ville: result[0].ville,
          users_details: {
            iduser: result[0].iduser,
            nom: result[0].nom,
            prenom: result[0].prenom,
            num: result[0].num,
            email: result[0].email
          },
          bien_details: {}
        };

        if (result[0].type === 'Terrain') {
          formattedData.bien_details.terrain = removeNullValues({
            categorie: result[0].terrain_categorie,
            largeur: result[0].terrain_largeur,
            longueur: result[0].terrain_longueur,
            meuble: result[0].terrain_meuble
          });
        } else if (result[0].type === 'Industriel') {
          formattedData.bien_details.industriel = removeNullValues({
            capacite: result[0].industriel_capacite,
            puissance: result[0].industriel_puissance,
            materiel: result[0].industriel_materiel,
            taille: result[0].industriel_taille,
            meuble: result[0].industriel_meuble
          });
        } else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence === 'Villa') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            equipement: result[0].résidentiel_equipement,
            type_residence: result[0].résidentiel_residence,
            etage_villa: result[0].villa_etage,
            type_villa: result[0].villa_type,
            Ascenseur:result[0].résidentiel_Ascenseur,
            Wifi:result[0].résidentiel_Wifi,
            Camera:result[0].résidentiel_Camera,
            Parking:result[0].résidentiel_Parking,
            Garage : result[0].résidentiel_Garage,
            Electroménager:result[0].résidentiel_Elec,
            Climatiseur: result[0].résidentiel_Clim,
            Citerne: result[0]. résidentiel_Citerne 
          });
        } else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence === 'Appartement') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            equipement: result[0].résidentiel_equipement,
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type,
            Ascenseur:result[0].résidentiel_Ascenseur,
            Wifi:result[0].résidentiel_Wifi,
            Camera:result[0].résidentiel_Camera,
            Parking:result[0].résidentiel_Parking,
            Garage : result[0].résidentiel_Garage,
            Electroménager:result[0].résidentiel_Elec,
            Climatiseur: result[0].résidentiel_Clim,
            Citerne: result[0]. résidentiel_Citerne 

          });
        } else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence === 'Maison') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            equipement: result[0].résidentiel_equipement,
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type,
            etage_maison: result[0].maison_etage,
            Ascenseur:result[0].résidentiel_Ascenseur,
            Wifi:result[0].résidentiel_Wifi,
            Camera:result[0].résidentiel_Camera,
            Parking:result[0].résidentiel_Parking,
            Garage : result[0].résidentiel_Garage,
            Electroménager:result[0].résidentiel_Elec,
            Climatiseur: result[0].résidentiel_Clim,
            Citerne: result[0]. résidentiel_Citerne 
          });
        } else if (result[0].type === 'Résidentiel' && result[0].résidentiel_residence === 'Studio') {
          formattedData.bien_details.résidentiel = removeNullValues({
            meuble: result[0].résidentiel_meuble,
            equipement: result[0].résidentiel_equipement,
            type_residence: result[0].résidentiel_residence,
            type_appartement: result[0].appartement_type,
            etage_maison: result[0].maison_etage,
            Ascenseur:result[0].résidentiel_Ascenseur,
            Wifi:result[0].résidentiel_Wifi,
            Camera:result[0].résidentiel_Camera,
            Parking:result[0].résidentiel_Parking,
            Garage : result[0].résidentiel_Garage,
            Electroménager:result[0].résidentiel_Elec,
            Climatiseur: result[0].résidentiel_Clim,
            Citerne: result[0]. résidentiel_Citerne 
          });
        } else if (result[0].type === 'Commercial') {
          formattedData.bien_details.commercial = removeNullValues({
            etage: result[0].commercial_etage,
            camera_surveillance: result[0].commercial_camera,
            Garage:result[0].commercial_Garage,
            Espace_Sup:result[0].commercial_Espace,
            meuble: result[0].commercial_meuble
          });
        }
        response.json(formattedData);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});


/*
 //section recement ajouter , recuperere les dernier annonce ajouter.
app.get("/api/v1/recement/annonces", (req, res) => {
  try {
    pool.query(

      " SELECT annonce.idann, annonce.titre, description,image1, image2, image3, image4, image5, iduser, ville, adresse, prix FROM annonce LEFT JOIN bien ON bien.idann = annonce.idann",
      (error, result) => {
        if (error) {
          console.log(error);
          res.json({ error: "Une erreur s'est produite lors de la récupération des annonces." });
          return;
        }
        
        // Triez les annonces par ID 1 2 3 4 5 
        result.sort((a, b) => b.idann - a.idann);
        // dayi labghit 3 4 lsl atan 12 aka
        const dixDernieresAnnonces = result.slice(0, 12);
        res.json({ annonces: dixDernieresAnnonces });
      }
    );
  } catch (error) {
    console.log(error);
    res.json({ error: "Une erreur s'est produite lors de la récupération des annonces." });
  }
});

*/


// recement ajouter
app.get("/api/v1/recemment/annonces", async (request, response) => {
  try {
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT('etage', commercial.etage)
          ELSE JSON_OBJECT()
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres`,
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({
            error:
              "Une erreur s'est produite lors de la récupération des détails de l'annonce.",
          });
        }
        if (result.length === 0) {
          return response.json({
            error: "Aucune annonce trouvée avec l'identifiant spécifié.",
          });
        }

        result.forEach((row) => {
          if (row.selected_data) {
            row.selected_data = JSON.parse(row.selected_data);
          }
          // Créer un tableau d'images à partir des propriétés image1 à image5
          const images = [];
          for (let i = 1; i <= 5; i++) {
            const imageKey = `image${i}`;
            if (row[imageKey]) {
              images.push(row[imageKey]);
            }
          }
          row.images = images;
        });
        const Res = result.slice(0, 12);
        response.json(Res);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({
      error:
        "Une erreur s'est produite lors de la récupération des détails de l'annonce.",
    });
  }
});


/*
app.get("/api/v1/recemment/annonces", async (request, response) => {
  try {
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT('equipement', commercial.equipement, 'etage', commercial.etage)
          ELSE JSON_OBJECT()


      
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres`,
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({
            error:
              "Une erreur s'est produite lors de la récupération des détails de l'annonce.",
          });
        }
        if (result.length === 0) {
          return response.json({
            error: "Aucune annonce trouvée avec l'identifiant spécifié.",
          });
        }

        result.forEach((row) => {
          if (row.selected_data) {
            row.selected_data = JSON.parse(row.selected_data);
          }
        });
        const Res = result.slice(0, 12);
        response.json(Res);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({
      error:
        "Une erreur s'est produite lors de la récupération des détails de l'annonce.",
    });
  }
});


*/

// recherche basique 
app.get("/api/v1/basiquee/recherche", (req, res) => {
  const { ville, prix } = req.query; 
  if (!ville || !prix) {
      return res.json({ error: "Veuillez fournir une ville et un prix." });
  }
  pool.query(
      "SELECT \
          CASE \
              WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur) \
              WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Commercial' THEN JSON_OBJECT( 'etage', commercial.etage) \
              ELSE JSON_OBJECT() \
          END AS selected_data, \
          annonce.titre, \
          annonce.description, \
          annonce.date_ajout, \
          annonce.image1, \
          annonce.image2, \
          annonce.image3, \
          annonce.image4, \
          annonce.image5, \
          annonce.iduser, \
          bien.idB, \
          bien.type, \
          bien.surface, \
          bien.prix, \
          bien.userId, \
          bien.idann, \
          bien.ville, \
          bien.adresse \
      FROM bien \
      INNER JOIN annonce ON bien.idann = annonce.idann \
      LEFT JOIN terrain ON bien.idB = terrain.idb \
      LEFT JOIN industriel ON bien.idB = industriel.idb \
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb \
      LEFT JOIN commercial ON bien.idB = commercial.idb \
      LEFT JOIN maison ON maison.idres = résidentiel.idres \
      LEFT JOIN villa ON villa.idres = résidentiel.idres \
      LEFT JOIN studio ON studio.idres = résidentiel.idres \
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres \
      WHERE bien.ville = ? AND bien.prix <= ?",
      [ville, prix],
      (error, result) => {
          if (error) {
              console.error(error);
              return res.json({ error: "Une erreur s'est produite lors de la recherche." });
          } else {
              result.forEach(item => {
                  item.selected_data = JSON.parse(item.selected_data);
                  // Créer un tableau d'images à partir des propriétés image1 à image5
                  const images = [];
                  for (let i = 1; i <= 5; i++) {
                      const imageKey = `image${i}`;
                      if (item[imageKey]) {
                          images.push(item[imageKey]);
                      }
                  }
                  item.images = images;
              });
              const response = {
                  totalListing: result.length,
                  listing: result
              };
              res.json(response);
          }
      }
  );
});


/*
app.get("/api/v1/basiquee/recherche", (req, res) => {
    const { ville, prix } = req.query; 
    if (!ville || !prix) {
        return res.json({ error: "Veuillez fournir une ville et un prix." });
    }
    pool.query(
        "SELECT \
            CASE \
                WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur) \
                WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
                WHEN bien.type = 'Commercial' THEN JSON_OBJECT('equipement', commercial.equipement, 'etage', commercial.etage) \
                ELSE JSON_OBJECT() \
            END AS selected_data, \
            annonce.titre, \
            annonce.description, \
            annonce.date_ajout, \
            annonce.image1, \
            annonce.image2, \
            annonce.image3, \
            annonce.image4, \
            annonce.image5, \
            annonce.iduser, \
            bien.idB, \
            bien.type, \
            bien.surface, \
            bien.prix, \
            bien.userId, \
            bien.idann, \
            bien.ville, \
            bien.adresse \
        FROM bien \
        INNER JOIN annonce ON bien.idann = annonce.idann \
        LEFT JOIN terrain ON bien.idB = terrain.idb \
        LEFT JOIN industriel ON bien.idB = industriel.idb \
        LEFT JOIN résidentiel ON bien.idB = résidentiel.idb \
        LEFT JOIN commercial ON bien.idB = commercial.idb \
        LEFT JOIN maison ON maison.idres = résidentiel.idres \
        LEFT JOIN villa ON villa.idres = résidentiel.idres \
        LEFT JOIN studio ON studio.idres = résidentiel.idres \
        LEFT JOIN appartement ON appartement.idres = résidentiel.idres \
        WHERE bien.ville = ? AND bien.prix <= ?",
        [ville, prix],
        (error, result) => {
            if (error) {
                console.error(error);
                return res.json({ error: "Une erreur s'est produite lors de la recherche." });
            } else {
               
                result.forEach(item => {
                    item.selected_data = JSON.parse(item.selected_data);
                });
                const response = {
                    totalListing: result.length,
                    listing: result
                };
                res.json(response);
            }
        }
    );
});

*/

/*
// recherche avancé 
app.get("/api/v1/avance/recherche", (req, res) => {
  const { ville, meuble, surface, type, prix } = req.query; 
  if (!ville || !prix) {
      return res.json({ error: "Veuillez fournir une ville et un prix." });
  }
  pool.query(
      "SELECT \
          CASE \
              WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur) \
              WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Commercial' THEN JSON_OBJECT('equipement', commercial.equipement, 'etage', commercial.etage) \
              ELSE JSON_OBJECT() \
          END AS selected_data, \
          annonce.titre, \
          annonce.description, \
          annonce.date_ajout, \
          annonce.image1, \
          annonce.image2, \
          annonce.image3, \
          annonce.image4, \
          annonce.image5, \
          annonce.iduser, \
          bien.idB, \
          bien.type, \
          bien.surface, \
          bien.prix, \
          bien.userId, \
          bien.idann, \
          bien.ville, \
          bien.adresse \
      FROM bien \
      INNER JOIN annonce ON bien.idann = annonce.idann \
      LEFT JOIN terrain ON bien.idB = terrain.idb \
      LEFT JOIN industriel ON bien.idB = industriel.idb \
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb \
      LEFT JOIN commercial ON bien.idB = commercial.idb \
      LEFT JOIN maison ON maison.idres = résidentiel.idres \
      LEFT JOIN villa ON villa.idres = résidentiel.idres \
      LEFT JOIN studio ON studio.idres = résidentiel.idres \
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres \
      WHERE ((résidentiel.meuble = ? OR résidentiel.meuble IS NULL) OR \
             (industriel.meuble = ? OR industriel.meuble IS NULL) OR \
             (commercial.meuble = ? OR commercial.meuble IS NULL) OR \
             (terrain.meuble = ? OR terrain.meuble IS NULL)) \
        AND bien.surface = ?\
        AND bien.ville = ? \
        AND bien.type = ?  \
        AND bien.prix <= ? ",
      [meuble, meuble, meuble, meuble, surface, ville, type, prix],
      (error, result) => {
          if (error) {
              console.error(error);
              return res.json({ error: "Une erreur s'est produite lors de la recherche." });
          } else {

            result.forEach(item => {
              item.selected_data = JSON.parse(item.selected_data);
          });
              const response = {
                  totalListing: result.length,
                  listing: result
              };
              res.json(response);
          }
      }
  );
});


*/

   // recherche avancé
app.get("/api/v1/avance/recherche", (req, res) => {
  const { ville, meuble, surface, type, prix } = req.query; 
  if (!ville || !prix) {
      return res.json({ error: "Veuillez fournir une ville et un prix." });
  }
  pool.query(
      "SELECT \
          CASE \
              WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur) \
              WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence) \
              WHEN bien.type = 'Commercial' THEN JSON_OBJECT( 'etage', commercial.etage) \
              ELSE JSON_OBJECT() \
          END AS selected_data, \
          annonce.titre, \
          annonce.description, \
          annonce.date_ajout, \
          annonce.image1, \
          annonce.image2, \
          annonce.image3, \
          annonce.image4, \
          annonce.image5, \
          annonce.iduser, \
          bien.idB, \
          bien.type, \
          bien.surface, \
          bien.prix, \
          bien.userId, \
          bien.idann, \
          bien.ville, \
          bien.adresse \
      FROM bien \
      INNER JOIN annonce ON bien.idann = annonce.idann \
      LEFT JOIN terrain ON bien.idB = terrain.idb \
      LEFT JOIN industriel ON bien.idB = industriel.idb \
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb \
      LEFT JOIN commercial ON bien.idB = commercial.idb \
      LEFT JOIN maison ON maison.idres = résidentiel.idres \
      LEFT JOIN villa ON villa.idres = résidentiel.idres \
      LEFT JOIN studio ON studio.idres = résidentiel.idres \
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres \
      WHERE ((résidentiel.meuble = ? OR résidentiel.meuble IS NULL) OR \
             (industriel.meuble = ? OR industriel.meuble IS NULL) OR \
             (commercial.meuble = ? OR commercial.meuble IS NULL) OR \
             (terrain.meuble = ? OR terrain.meuble IS NULL)) \
        AND bien.surface = ?\
        AND bien.ville = ? \
        AND bien.type = ?  \
        AND bien.prix <= ? ",
      [meuble, meuble, meuble, meuble, surface, ville, type, prix],
      (error, result) => {
          if (error) {
              console.error(error);
              return res.json({ error: "Une erreur s'est produite lors de la recherche." });
          } else {
              result.forEach(item => {
                  item.selected_data = JSON.parse(item.selected_data);
                  // Créer un tableau d'images à partir des propriétés image1 à image5
                  const images = [];
                  for (let i = 1; i <= 5; i++) {
                      const imageKey = `image${i}`;
                      if (item[imageKey]) {
                          images.push(item[imageKey]);
                      }
                  }
                  item.images = images;
              });

              const response = {
                  totalListing: result.length,
                  listing: result
              };
              res.json(response);
          }
      }
  );
});

// afficher le tout meme les table maison ....
app.get("/api/v1/info/pr/annonce", async (request, response) => {
  try {
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT( 'etage', commercial.etage)
          ELSE JSON_OBJECT()
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres`,
      (err, result) => {
        if (err) {
          console.error(err);
          return response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }

        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec l'identifiant spécifié." });
        }
        
        result.forEach(row => {
          // Créez un tableau pour stocker les images
          row.images = [];
          // Parcourez les images et ajoutez-les au tableau
          for (let i = 1; i <= 5; i++) {
            const imageField = 'image' + i;
            if (row[imageField]) {
              row.images.push(row[imageField]);
              // Supprimez le champ d'image individuelle
              delete row[imageField];
            }
          }
          if (row.selected_data) {
            row.selected_data = JSON.parse(row.selected_data);
          }
        });

        response.json(result);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});

/*
app.post("/api/v1/favoris", (req, res) => {
  const { idann } = req.body;
  pool.query(
   "INSERT INTO favoris (idc, idn, titre, description, image1, image2, image3, image4, image5, ville, adresse, prix, meuble, surface, type, type_residence) SELECT annonce.iduser AS idc, annonce.idann AS idn, annonce.titre AS titre, annonce.description AS description, annonce.image1 AS image1, annonce.image2 AS image2, annonce.image3 AS image3, annonce.image4 AS image4, annonce.image5 AS image5, bien.ville AS ville, bien.adresse AS adresse, bien.prix AS prix, CASE WHEN bien.type = 'Résidentiel' THEN résidentiel.meuble ELSE NULL END AS meuble, bien.surface AS surface, bien.type AS type, CASE WHEN bien.type = 'Résidentiel' THEN résidentiel.type_residence ELSE NULL END AS type_residence FROM annonce INNER JOIN bien ON bien.idann = annonce.idann LEFT JOIN résidentiel ON bien.idB = résidentiel.idb WHERE annonce.idann = ?",
    [idann],
    (error, result) => {
      if (error) {
        console.error(error);
        res.json({
          error:

            "Une erreur s'est produite lors de l'ajout de l'annonce aux favoris.",
        });
        return;
      }

      res.json({
        success: true,
        message: "Annonce ajoutée aux favoris avec succès.",
      });
    }
  );
});


*/


app.post("/api/v1/favoris",auth, (req, res) => {
  const { idann } = req.body;
  pool.query(

    "INSERT INTO favoris (idc, idn, titre, description, images, ville, adresse, prix, meuble, surface, type, type_residence) SELECT annonce.iduser AS idc, annonce.idann AS idn, annonce.titre AS titre, annonce.description AS description, JSON_ARRAY(annonce.image1, annonce.image2, annonce.image3, annonce.image4, annonce.image5) AS images, bien.ville AS ville, bien.adresse AS adresse, bien.prix AS prix, CASE WHEN bien.type = 'Résidentiel' THEN résidentiel.meuble ELSE NULL END AS meuble, bien.surface AS surface, bien.type AS type, CASE WHEN bien.type = 'Résidentiel' THEN résidentiel.type_residence ELSE NULL END AS type_residence FROM annonce INNER JOIN bien ON bien.idann = annonce.idann LEFT JOIN résidentiel ON bien.idB = résidentiel.idb WHERE annonce.idann = ?",
    [idann],
    (error, result) => {
      if (error) {
        console.error(error);
        res.json({
          error: "Une erreur s'est produite lors de l'ajout de l'annonce aux favoris.",
        });
        return;
      }

      res.json({
        success: true,
        message: "Annonce ajoutée aux favoris avec succès.",
      });
    }
  );
});

/*

app.get("/api/v1/favoris", (req, res) => {
  pool.query("SELECT * FROM favoris", (error, results) => {
    if (error) {
      console.error(error);
      res.json({
        error:
          "Une erreur s'est produite lors de la récupération des annonces favorites.",
      });
      return;
    }

    res.json({ favoris: results });
  });
});



*/

app.get("/api/v1/favoris",auth,(req, res) => {
  pool.query("SELECT idc,idn, titre, description, image1, image2, image3, image4, image5, ville, adresse, prix, meuble, surface, type, type_residence FROM favoris", (error, results) => {
    if (error) {
      console.error(error);
      res.json({
        error: "Une erreur s'est produite lors de la récupération des annonces favorites.",
      });
      return;
    }

    results.forEach(row => {
      row.images = [];
      for (let i = 1; i <= 5; i++) {
        const imageField = 'image' + i;
        if (row[imageField]) {
          row.images.push(row[imageField]);
          delete row[imageField];
        }
      }
    });

    res.json({ favoris: results });
  });
});

 


app.delete("/api/v1/favoris", auth, (req, res) => {
  const { idan } = req.body;
  pool.query(
    "DELETE  FROM favoris WHERE idn=?",
     [idan] ,
      (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Une erreur s'est produite lors de la suppression de l'annonce favorite." });
    }
    res.status(200).json({ message: "L'annonce favorite a été supprimée avec succès." });
  });
});

 




// ville de bien ( pour la page home)

app.get("/api/v1/ville/annonces/:ville", async (request, response) => {
  try {
    const ville = request.params.ville;
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT('etage', commercial.etage)
          ELSE JSON_OBJECT()
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse,
        terrain.categorie AS terrain_categorie,
        terrain.largeur AS terrain_largeur,
        terrain.longueur AS terrain_longueur,
        industriel.puissance AS industriel_puissance,
        industriel.materiel AS industriel_materiel,
        industriel.taille AS industriel_taille,
        maison.etage_maison AS maison_etage_maison,
        résidentiel.meuble AS résidentiel_meuble,
        résidentiel.equipement AS résidentiel_equipement,
        résidentiel.type_residence AS résidentiel_residence,
        villa.etage_villa AS villa_etage_villa,
        villa.type_villa AS villa_type_villa,
        studio.idStu AS studio_idStu,
        appartement.type_appartement AS appartement_type_appartement,
        commercial.etage AS commercial_etage
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres
      WHERE bien.ville = ?`,
      [ville],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.status(500).json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec la ville spécifiée." });
        }
        // Formater les données
        const formattedData = result.map(row => {
          const images = [];
          for (let i = 1; i <= 5; i++) {
            if (row[`image${i}`]) {
              images.push(row[`image${i}`]);
            }
          }
          let selectedData;
          switch (row.type) {
            case 'Terrain':
              selectedData = {
                categorie: row.terrain_categorie,
                largeur: row.terrain_largeur,
                longueur: row.terrain_longueur
              };
              break;
            case 'Industriel':
              selectedData = {
                puissance: row.industriel_puissance,
                materiel: row.industriel_materiel,
                taille: row.industriel_taille
              };
              break;
            case 'Résidentiel':
              switch (row.résidentiel_residence) {
                case 'Maison':
                  selectedData = {
                    etage_maison: row.maison_etage_maison,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Villa':
                  selectedData = {
                    etage_villa: row.villa_etage_villa,
                    type_villa: row.villa_type_villa,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Studio':
                  selectedData = {
                    idStu: row.studio_idStu,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Appartement':
                  selectedData = {
                    type_appartement: row.appartement_type_appartement,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                default:
                  selectedData = {};
              }
              break;
            case 'Commercial':
              selectedData = {
                equipement: row.commercial_equipement,
                etage: row.commercial_etage
              };
              break;
            default:
              selectedData = {};
          }

          return {
            titre: row.titre,
            description: row.description,
            date_ajout: row.date_ajout,
            images: images,
            iduser: row.iduser,
            idB: row.idB,
            type: row.type,
            surface: row.surface,
            prix: row.prix,
            userId: row.userId,
            idann: row.idann,
            adresse: row.adresse,
            ville: row.ville,
            bien_details: selectedData
          };
        });
        response.json(formattedData);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});


// type de bien ( pour la page home)

app.get("/api/v1/type/annonces/:type", async (request, response) => {
  try {
    const ville = request.params.type;
    await pool.query(
      `SELECT
        CASE
          WHEN bien.type = 'Terrain' THEN JSON_OBJECT('categorie', terrain.categorie, 'largeur', terrain.largeur, 'longueur', terrain.longueur)
          WHEN bien.type = 'Industriel' THEN JSON_OBJECT('puissance', industriel.puissance, 'materiel', industriel.materiel, 'taille', industriel.taille)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Maison' THEN JSON_OBJECT('etage_maison', maison.etage_maison, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Villa' THEN JSON_OBJECT('etage_villa', villa.etage_villa, 'type_villa', villa.type_villa, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Studio' THEN JSON_OBJECT('idStu', studio.idStu, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Résidentiel' AND résidentiel.type_residence = 'Appartement' THEN JSON_OBJECT('type_appartement', appartement.type_appartement, 'meuble', résidentiel.meuble, 'equipement', résidentiel.equipement, 'type_residence', résidentiel.type_residence)
          WHEN bien.type = 'Commercial' THEN JSON_OBJECT('etage', commercial.etage)
          ELSE JSON_OBJECT()
        END AS selected_data,
        annonce.titre, 
        annonce.description, 
        annonce.date_ajout, 
        annonce.image1, 
        annonce.image2, 
        annonce.image3, 
        annonce.image4, 
        annonce.image5, 
        annonce.iduser, 
        bien.idB, 
        bien.type, 
        bien.surface, 
        bien.prix, 
        bien.userId, 
        bien.idann,
        bien.ville,
        bien.adresse,
        terrain.categorie AS terrain_categorie,
        terrain.largeur AS terrain_largeur,
        terrain.longueur AS terrain_longueur,
        industriel.puissance AS industriel_puissance,
        industriel.materiel AS industriel_materiel,
        industriel.taille AS industriel_taille,
        maison.etage_maison AS maison_etage_maison,
        résidentiel.meuble AS résidentiel_meuble,
        résidentiel.equipement AS résidentiel_equipement,
        résidentiel.type_residence AS résidentiel_residence,
        villa.etage_villa AS villa_etage_villa,
        villa.type_villa AS villa_type_villa,
        studio.idStu AS studio_idStu,
        appartement.type_appartement AS appartement_type_appartement,
        commercial.etage AS commercial_etage
      FROM bien
      INNER JOIN annonce ON bien.idann = annonce.idann
      LEFT JOIN terrain ON bien.idB = terrain.idb
      LEFT JOIN industriel ON bien.idB = industriel.idb
      LEFT JOIN résidentiel ON bien.idB = résidentiel.idb
      LEFT JOIN commercial ON bien.idB = commercial.idb
      LEFT JOIN maison ON maison.idres = résidentiel.idres
      LEFT JOIN villa ON villa.idres = résidentiel.idres
      LEFT JOIN studio ON studio.idres = résidentiel.idres
      LEFT JOIN appartement ON appartement.idres = résidentiel.idres
      WHERE bien.type = ?`,
      [ville],
      (err, result) => {
        if (err) {
          console.error(err);
          return response.status(500).json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
        }
        if (result.length === 0) {
          return response.json({ error: "Aucune annonce trouvée avec la ville spécifiée." });
        }
        // Formater les données
        const formattedData = result.map(row => {
          const images = [];
          for (let i = 1; i <= 5; i++) {
            if (row[`image${i}`]) {
              images.push(row[`image${i}`]);
            }
          }
          let selectedData;
          switch (row.type) {
            case 'Terrain':
              selectedData = {
                categorie: row.terrain_categorie,
                largeur: row.terrain_largeur,
                longueur: row.terrain_longueur
              };
              break;
            case 'Industriel':
              selectedData = {
                puissance: row.industriel_puissance,
                materiel: row.industriel_materiel,
                taille: row.industriel_taille
              };
              break;
            case 'Résidentiel':
              switch (row.résidentiel_residence) {
                case 'Maison':
                  selectedData = {
                    etage_maison: row.maison_etage_maison,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Villa':
                  selectedData = {
                    etage_villa: row.villa_etage_villa,
                    type_villa: row.villa_type_villa,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Studio':
                  selectedData = {
                    idStu: row.studio_idStu,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                case 'Appartement':
                  selectedData = {
                    type_appartement: row.appartement_type_appartement,
                    meuble: row.résidentiel_meuble,
                    equipement: row.résidentiel_equipement,
                    type_residence: row.résidentiel_residence
                  };
                  break;
                default:
                  selectedData = {};
              }
              break;
            case 'Commercial':
              selectedData = {
                equipement: row.commercial_equipement,
                etage: row.commercial_etage
              };
              break;
            default:
              selectedData = {};
          }

          return {
            titre: row.titre,
            description: row.description,
            date_ajout: row.date_ajout,
            images: images,
            iduser: row.iduser,
            idB: row.idB,
            type: row.type,
            surface: row.surface,
            prix: row.prix,
            userId: row.userId,
            idann: row.idann,
            adresse: row.adresse,
            ville: row.ville,
            bien_details: selectedData
          };
        });
        response.json(formattedData);
      }
    );
  } catch (error) {
    console.error(error);
    response.json({ error: "Une erreur s'est produite lors de la récupération des détails de l'annonce." });
  }
});

app.listen(3000,()=>{
console.log("I am listen what kho ")
})





















