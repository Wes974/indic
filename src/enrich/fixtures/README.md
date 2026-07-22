# Fixtures d'enrichers

Réponses **réelles** capturées sur les API, rejouées dans les tests.

## Pourquoi

Les tests écrits à la main valident la logique de parsing contre la forme qu'on
*croit* que l'API renvoie. Ils n'attrapent pas le cas qui casse vraiment : le
service change de forme et le parseur, lui, ne bouge pas.

Deux occurrences réelles dans ce dépôt :

- **IntelX** renvoyait `"records": null` là où le type attendait un tableau.
  `#[serde(default)]` ne couvre que le champ *absent*, pas le champ *nul* — la
  désérialisation échouait sur toutes les réponses sans résultat.
- **Traceix** documente `results: {sha256, capabilities: […]}` et renvoie en
  réalité un tableau plat. Un parseur écrit sur la seule foi de la doc aurait
  affiché « format non reconnu » sur 100 % des réponses valides.

Une fixture enregistrée sur la vraie API aurait signalé les deux immédiatement.

## Comment en ajouter une

1. Capturer la réponse brute :

   ```bash
   curl -s -X POST https://exemple.tld/api/endpoint \
        -H 'content-type: application/json' -d '{"q":"…"}' \
        -o src/enrich/fixtures/<source>-<cas>.json
   ```

2. **Retirer tout secret** — clé d'API, token, identifiant de compte. Un test
   (`fixtures_contain_no_secret`) échoue si un motif sensible traîne, mais il
   ne remplace pas une relecture.

3. La rejouer dans le test du module :

   ```rust
   #[test]
   fn parses_the_recorded_response() {
       let env = serde_json::from_str(include_str!("fixtures/<source>-<cas>.json")).unwrap();
       let e = build(&env);
       assert!(e.error.is_none());
   }
   ```

Un test vérifie qu'aucune fixture n'est orpheline : toute fixture doit être
référencée par au moins un `include_str!`, sinon elle vieillit sans que
personne ne s'en aperçoive.

## Ce que ces fixtures ne font pas

Elles figent une réponse à un instant donné. Elles détectent qu'un parseur
casse sur une forme **connue** ; elles ne préviennent pas d'un changement
d'API à venir. Pour ça, il faut les recapturer périodiquement — le
`request_timestamp` présent dans chaque fichier indique de quand elles datent.
